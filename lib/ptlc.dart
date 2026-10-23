import 'dart:async';
import 'dart:io';
import 'dart:math';

import 'package:collection/collection.dart';
import 'package:convert/convert.dart';
import 'package:dcli/dcli.dart' hide verbose;
import 'package:znn_cli_dart/lib.dart';
import 'package:znn_sdk_dart/znn_sdk_dart.dart';

const int ptlcRevealMargin = 60;
const int ptlcTimelockMinHours = 1;
const int ptlcTimelockMaxHours = 24 * 7;

void ptlcMenu() {
  print('  ${white('PTLC')}');
  print(
      '    ptlc.create tokenStandard amount expirationTime (in hours) pointType pointLock [destination]');
  print('    ptlc.unlock id [witness]');
  print('    ptlc.proxyUnlock id destination witness');
  print('    ptlc.reclaim id');
  print('    ptlc.get id');
  print('    ptlc.inspect blockHash');
  print('    ptlc.monitor id');
  print('    ptlc.message id destination pointType');
  print('    ptlc.sign id destination secretKey [pointType]');
  print('    ptlc.keygen');
  print('    ptlc.point secret');
  print('    ptlc.tweak point tweak');
  print('    ptlc.tweakSecret secret tweak');
  print('    ptlc.adaptorSign secretKey message adaptorPoint');
  print('    ptlc.adaptorVerify publicKey message adaptorPoint preSignature');
  print('    ptlc.adaptorComplete preSignature secret');
  print('    ptlc.adaptorExtract preSignature signature');
}

Future<void> ptlcFunctions() async {
  switch (args[0].split('.')[1]) {
    case 'create':
      verbose ? print('Description: Create a ptlc') : null;
      await _create();
      return;

    case 'unlock':
      verbose
          ? print('Description: Unlock an active ptlc to this address')
          : null;
      await _unlock();
      return;

    case 'proxyUnlock':
      verbose
          ? print('Description: Unlock an active ptlc to another address')
          : null;
      await _proxyUnlock();
      return;

    case 'reclaim':
      verbose ? print('Description: Reclaim an expired ptlc') : null;
      await _reclaim();
      return;

    case 'get':
      verbose ? print('Description: Display ptlc details') : null;
      await _get();
      return;

    case 'inspect':
      verbose ? print('Description: Inspect ptlc account-block') : null;
      await _inspect();
      return;

    case 'monitor':
      verbose
          ? print(
              'Description: Monitor ptlc by id -- automatically reclaim it or display its witness')
          : null;
      await _monitor();
      return;

    case 'message':
      verbose
          ? print('Description: Display the unlock message a key must sign')
          : null;
      await _message();
      return;

    case 'sign':
      verbose
          ? print('Description: Sign the unlock message with a secret key')
          : null;
      await _sign();
      return;

    case 'keygen':
      verbose
          ? print('Description: Generate a secp256k1 secret and its points')
          : null;
      _keygen();
      return;

    case 'point':
      verbose ? print('Description: Display the points of a secret') : null;
      _point();
      return;

    case 'tweak':
      verbose ? print('Description: Add a tweak to a point') : null;
      _tweak();
      return;

    case 'tweakSecret':
      verbose ? print('Description: Add a tweak to a secret') : null;
      _tweakSecret();
      return;

    case 'adaptorSign':
      verbose ? print('Description: Create a BIP-340 pre-signature') : null;
      _adaptorSign();
      return;

    case 'adaptorVerify':
      verbose ? print('Description: Verify a BIP-340 pre-signature') : null;
      _adaptorVerify();
      return;

    case 'adaptorComplete':
      verbose
          ? print('Description: Complete a pre-signature with the secret')
          : null;
      _adaptorComplete();
      return;

    case 'adaptorExtract':
      verbose
          ? print(
              'Description: Extract the secret from a pre-signature and its signature')
          : null;
      _adaptorExtract();
      return;

    default:
      invalidCommand();
  }
}

String ptlcPointTypeName(int pointType) {
  switch (pointType) {
    case ptlcPointTypeEd25519:
      return 'Ed25519 key';
    case ptlcPointTypeBip340:
      return 'BIP-340 key';
    case ptlcPointTypeSecp256k1Point:
      return 'secp256k1 point';
    default:
      return 'unknown ($pointType)';
  }
}

String? ptlcRevealProblem(PtlcInfo ptlc, int now) {
  final left = ptlc.expirationTime - now;
  if (left <= 0) {
    return 'Cannot unlock ptlc. Time lock expired';
  }
  if (left < ptlcRevealMargin) {
    return 'Cannot unlock ptlc. Only ${left}s left before it expires, less than the ${ptlcRevealMargin}s an unlock needs to be confirmed';
  }
  return null;
}

bool ptlcCallAccepted(List<int>? data) =>
    data != null &&
    data.length == 8 &&
    Secp256k1.bytesToBigInt(data) == BigInt.one;

AbiFunction? ptlcFunction(List<int> data) {
  if (data.length < AbiFunction.encodedSignLength) {
    return null;
  }
  for (var entry in Definitions.ptlc.entries) {
    if (const ListEquality().equals(
        AbiFunction.extractSignature(entry.encodeSignature()),
        AbiFunction.extractSignature(data))) {
      return AbiFunction(entry.name!, entry.inputs!);
    }
  }
  return null;
}

List<int> _hex(String value, String name, [int? length]) {
  final clean = value.startsWith('0x') ? value.substring(2) : value;
  List<int> bytes;
  try {
    bytes = hex.decode(clean);
  } catch (e) {
    print('${red('Error!')} $name is not valid hex');
    exit(-1);
  }
  if (length != null && bytes.length != length) {
    print('${red('Error!')} $name must be $length bytes');
    exit(-1);
  }
  return bytes;
}

BigInt _scalar(String value, String name) {
  final scalar = Secp256k1.parseScalar(_hex(value, name, 32));
  if (scalar == null) {
    print('${red('Error!')} $name is not a valid secp256k1 scalar');
    exit(-1);
  }
  return scalar;
}

List<int> _randomBytes(int length) {
  final random = Random.secure();
  return List<int>.generate(length, (_) => random.nextInt(256));
}

String _format(Duration d) => d.toString().split('.').first.padLeft(8, '0');

Future<PtlcInfo> _getById(Hash id) async {
  try {
    return await znnClient.embedded.ptlc.getById(id);
  } catch (e) {
    print('${red('Error!')} The ptlc id $id does not exist');
    exit(-1);
  }
}

Future<Momentum> _frontier() async => znnClient.ledger.getFrontierMomentum();

Future<bool> _lockIsOurKey(PtlcInfo ptlc) async {
  if (ptlc.pointType != ptlcPointTypeEd25519) {
    return false;
  }
  final ours = await znnClient.defaultKeyPair!.getPublicKey();
  return const ListEquality().equals(ours, ptlc.pointLock);
}

Future<bool> _checkWitness(PtlcInfo ptlc, int chainIdentifier,
    Address destination, List<int> witness) async {
  if (!await PtlcApi.verifyWitness(chainIdentifier, ptlc.pointType,
      ptlc.pointLock, ptlc.id, destination, witness)) {
    print(ptlc.pointType == ptlcPointTypeSecp256k1Point
        ? '${red('Error!')} the witness is not the secret of the point lock'
        : '${red('Error!')} the witness does not verify for this ptlc and destination $destination');
    return false;
  }
  return true;
}

Future<void> _create() async {
  if (args.length < 6 || args.length > 7) {
    print('Incorrect number of arguments. Expected:');
    print(
        'ptlc.create tokenStandard amount expirationTime (in hours) pointType pointLock [destination]');
    print('Supported point types:');
    print('  0: Ed25519 key (32 bytes)');
    print('  1: BIP-340 key (32 bytes, x-only)');
    print(
        '  2: secp256k1 point (33 bytes, compressed), requires a destination');
    return;
  }

  TokenStandard tokenStandard = getTokenStandard(args[1]);
  Token token = await getToken(tokenStandard);
  BigInt amount = AmountUtils.extractDecimals(args[2], token.decimals);
  Function color = getColor(tokenStandard);

  if (amount <= BigInt.zero) {
    print('${red('Error!')} amount must be greater than 0');
    return;
  }

  if (!await hasBalance(address, tokenStandard, amount)) {
    return;
  }

  int expirationTime;
  try {
    expirationTime = int.parse(args[3]);
  } catch (e) {
    print('${red('Error!')} expirationTime must be an integer.');
    return;
  }
  if (expirationTime < ptlcTimelockMinHours ||
      expirationTime > ptlcTimelockMaxHours) {
    print(
        '${red('Error!')} expirationTime (hours) must be at least $ptlcTimelockMinHours and at most $ptlcTimelockMaxHours.');
    return;
  }

  int pointType;
  try {
    pointType = int.parse(args[4]);
  } catch (e) {
    print('${red('Error!')} point type must be an integer.');
    return;
  }
  if (!ptlcPointLockSizes.containsKey(pointType)) {
    print('${red('Error!')} point type $pointType is not supported');
    return;
  }

  List<int> pointLock = _hex(args[5], 'pointLock');
  String? problem = Validations.ptlcPointLock(pointType, pointLock);
  if (problem != null) {
    print('${red('Error!')} $problem');
    return;
  }

  Address destination = emptyAddress;
  if (args.length == 7) {
    destination = parseAddress(args[6]);
  }
  problem = Validations.ptlcDestination(pointType, destination);
  if (problem != null) {
    print('${red('Error!')} $problem');
    return;
  }

  final duration = Duration(hours: expirationTime);
  final expiresAt = (await _frontier()).timestamp + duration.inSeconds;

  print(
      'Creating ptlc with amount ${AmountUtils.addDecimals(amount, token.decimals)} ${color(token.symbol)}');
  print(
      '  Point type ${ptlcPointTypeName(pointType)}, point lock ${green(hex.encode(pointLock))}');
  print(destination == emptyAddress
      ? '  Can be unlocked to any address the witness is signed for'
      : '  Can be unlocked only to $destination');
  print('  Can be reclaimed in ${_format(duration)} by $address');

  AccountBlockTemplate block = await send(znnClient.embedded.ptlc
      .create(token, amount, expiresAt, pointType, pointLock, destination));

  print('Submitted ptlc with id ${green(block.hash.toString())}');
  print('Done');
}

Future<void> _unlock() async {
  if (args.length < 2 || args.length > 3) {
    print('Incorrect number of arguments. Expected:');
    print('ptlc.unlock id [witness]');
    return;
  }

  Hash id = parseHash(args[1]);
  PtlcInfo ptlc = await _getById(id);
  Momentum frontier = await _frontier();

  String? problem = ptlcRevealProblem(ptlc, frontier.timestamp);
  if (problem != null) {
    print('${red('Error!')} $problem');
    return;
  }
  if (ptlc.hasFixedDestination && ptlc.destination != address) {
    print(
        '${red('Error!')} Cannot unlock ptlc to $address. It can only be unlocked to ${ptlc.destination}');
    return;
  }

  List<int> witness;
  if (args.length == 3) {
    witness = _hex(args[2], 'witness');
  } else if (await _lockIsOurKey(ptlc)) {
    witness = await znnClient.defaultKeyPair!.sign(PtlcApi.unlockMessage(
        frontier.chainIdentifier, ptlc.pointType, id, address));
  } else {
    print(
        '${red('Error!')} The point lock is not the key of $address. A witness is required');
    return;
  }

  problem = Validations.ptlcWitness(ptlc.pointType, witness);
  if (problem != null) {
    print('${red('Error!')} $problem');
    return;
  }
  if (!await _checkWitness(ptlc, frontier.chainIdentifier, address, witness)) {
    return;
  }

  Token token = await getToken(ptlc.tokenStandard);
  Function color = getColor(ptlc.tokenStandard);
  print(
      'Unlocking ptlc id ${ptlc.id} with amount ${AmountUtils.addDecimals(ptlc.amount, token.decimals)} ${color(token.symbol)}');
  await send(znnClient.embedded.ptlc.unlock(id, witness));
  print('Done');
  print(
      'Use ${green('receiveAll')} to collect your ptlc amount after 2 momentums');
}

Future<void> _proxyUnlock() async {
  if (args.length != 4) {
    print('Incorrect number of arguments. Expected:');
    print('ptlc.proxyUnlock id destination witness');
    return;
  }

  Hash id = parseHash(args[1]);
  Address destination = parseAddress(args[2]);
  List<int> witness = _hex(args[3], 'witness');
  PtlcInfo ptlc = await _getById(id);
  Momentum frontier = await _frontier();

  if (!assertUserAddress(destination)) {
    return;
  }
  String? problem = ptlcRevealProblem(ptlc, frontier.timestamp);
  if (problem != null) {
    print('${red('Error!')} $problem');
    return;
  }
  if (ptlc.hasFixedDestination && ptlc.destination != destination) {
    print(
        '${red('Error!')} Cannot unlock ptlc to $destination. It can only be unlocked to ${ptlc.destination}');
    return;
  }
  problem = Validations.ptlcWitness(ptlc.pointType, witness);
  if (problem != null) {
    print('${red('Error!')} $problem');
    return;
  }
  if (!await _checkWitness(
      ptlc, frontier.chainIdentifier, destination, witness)) {
    return;
  }

  Token token = await getToken(ptlc.tokenStandard);
  Function color = getColor(ptlc.tokenStandard);
  print(
      'Unlocking ptlc id ${ptlc.id} with amount ${AmountUtils.addDecimals(ptlc.amount, token.decimals)} ${color(token.symbol)} to $destination');
  await send(znnClient.embedded.ptlc.proxyUnlock(id, destination, witness));
  print('Done');
}

Future<void> _reclaim() async {
  if (args.length != 2) {
    print('Incorrect number of arguments. Expected:');
    print('ptlc.reclaim id');
    return;
  }

  Hash id = parseHash(args[1]);
  PtlcInfo ptlc = await _getById(id);
  int now = (await _frontier()).timestamp;

  if (ptlc.expirationTime > now) {
    print(
        '${red('Error!')} Cannot reclaim ptlc. Try again in ${_format(Duration(seconds: ptlc.expirationTime - now))}.');
    return;
  }

  if (ptlc.timeLocked != address) {
    print('${red('Error!')} Cannot reclaim ptlc. Permission denied');
    return;
  }

  Token token = await getToken(ptlc.tokenStandard);
  Function color = getColor(ptlc.tokenStandard);
  print(
      'Reclaiming ptlc id ${ptlc.id} with amount ${AmountUtils.addDecimals(ptlc.amount, token.decimals)} ${color(token.symbol)}');
  await send(znnClient.embedded.ptlc.reclaim(id));
  print('Done');
  print(
      'Use ${green('receiveAll')} to collect your ptlc amount after 2 momentums');
}

Future<void> _get() async {
  if (args.length != 2) {
    print('Incorrect number of arguments. Expected:');
    print('ptlc.get id');
    return;
  }

  Hash id = parseHash(args[1]);
  PtlcInfo ptlc = await _getById(id);
  await _printInfo(ptlc, (await _frontier()).timestamp);
  print('Done');
}

Future<void> _printInfo(PtlcInfo ptlc, int now) async {
  Token token = await getToken(ptlc.tokenStandard);
  Function color = getColor(ptlc.tokenStandard);
  print(
      'Ptlc id ${ptlc.id} with amount ${AmountUtils.addDecimals(ptlc.amount, token.decimals)} ${color(token.symbol)}');
  print(
      '   Point type ${ptlcPointTypeName(ptlc.pointType)}, point lock ${hex.encode(ptlc.pointLock)}');
  if (ptlc.expirationTime > now) {
    print(ptlc.hasFixedDestination
        ? '   Can be unlocked to ${ptlc.destination}'
        : '   Can be unlocked to any address the witness is signed for');
    print(
        '   Can be reclaimed in ${_format(Duration(seconds: ptlc.expirationTime - now))} by ${ptlc.timeLocked}');
  } else {
    print('   Can be reclaimed now by ${ptlc.timeLocked}');
  }
}

Future<void> _inspect() async {
  if (args.length != 2) {
    print('Incorrect number of arguments. Expected:');
    print('ptlc.inspect blockHash');
    return;
  }

  Hash blockHash = parseHash(args[1]);
  var block = await znnClient.ledger.getAccountBlockByHash(blockHash);

  if (block == null) {
    print('The account block ${blockHash.toString()} does not exist');
    return;
  }

  if (block.pairedAccountBlock == null ||
      block.blockType != BlockTypeEnum.userSend.index) {
    print('The account block was not sent by a user');
    return;
  }

  final f = ptlcFunction(block.data);
  if (f == null) {
    print('The account block contains invalid data');
    return;
  }

  var txArgs = f.decode(block.data);
  switch (f.name.toString()) {
    case 'Unlock':
      print(
          'Unlock ptlc: id ${cyan(txArgs[0].toString())} unlocked by ${block.address} with witness: ${green(hex.encode(txArgs[1]))}');
      break;
    case 'ProxyUnlock':
      print(
          'ProxyUnlock ptlc: id ${cyan(txArgs[0].toString())} unlocked by ${block.address} to ${txArgs[1]} with witness: ${green(hex.encode(txArgs[2]))}');
      break;
    case 'Reclaim':
      print(
          'Reclaim ptlc: id ${red(txArgs[0].toString())} reclaimed by ${block.address}');
      break;
    case 'Create':
      print('Create ptlc: '
          '${AmountUtils.addDecimals(block.amount, block.token!.decimals)} '
          '${block.token!.symbol} ${txArgs[0]} '
          '${txArgs[1]} '
          '${hex.encode(txArgs[2])} '
          '${txArgs[3]} '
          'created by ${block.address}');
      break;
    default:
      print('The account block contains an unknown function call');
  }
}

Future<void> _monitor() async {
  if (args.length != 2) {
    print('Incorrect number of arguments. Expected:');
    print('ptlc.monitor id');
    return;
  }

  Hash id = parseHash(args[1]);
  PtlcInfo ptlc = await _getById(id);
  Momentum frontier = await _frontier();
  await _printInfo(ptlc, frontier.timestamp);
  print('Monitoring ptlc id ${cyan(ptlc.id.toString())}');
  final chainIdentifier = frontier.chainIdentifier;

  var lastHeight =
      (await znnClient.ledger.getFrontierAccountBlock(ptlcAddress))?.height ??
          0;

  while (true) {
    await Future.delayed(const Duration(seconds: 10));
    frontier = await _frontier();
    final head =
        (await znnClient.ledger.getFrontierAccountBlock(ptlcAddress))?.height ??
            0;
    for (var height = lastHeight + 1; height <= head; height++) {
      final blocks = await znnClient.ledger
          .getAccountBlocksByHeight(ptlcAddress, height, 1);
      for (final block in blocks.list ?? <AccountBlock>[]) {
        if (block.blockType != BlockTypeEnum.contractReceive.index) {
          continue;
        }
        final paired = block.pairedAccountBlock;
        if (paired == null) {
          continue;
        }
        final f = ptlcFunction(paired.data);
        if (f == null || f.name == 'Create') {
          continue;
        }
        final txArgs = f.decode(paired.data);
        if (txArgs[0].toString() != id.toString()) {
          continue;
        }
        if (!ptlcCallAccepted(block.data)) {
          print(
              '${f.name} of ptlc id ${ptlc.id} by ${paired.address} was rejected');
          continue;
        }
        if (f.name == 'Reclaim') {
          print(
              'Ptlc id ${red(ptlc.id.toString())} reclaimed by ${paired.address}');
          print('Done');
          return;
        }
        final proxy = f.name == 'ProxyUnlock';
        final destination =
            proxy ? parseAddress(txArgs[1].toString()) : paired.address;
        final witness = List<int>.from(proxy ? txArgs[2] : txArgs[1]);
        if (!await PtlcApi.verifyWitness(chainIdentifier, ptlc.pointType,
            ptlc.pointLock, ptlc.id, destination, witness)) {
          print(
              '${red('Error!')} Ptlc id ${ptlc.id} was unlocked to $destination with a witness that does not verify');
          exit(-1);
        }
        print(
            'Ptlc id ${cyan(ptlc.id.toString())} unlocked to $destination with witness: ${green(hex.encode(witness))}');
        print('Done');
        return;
      }
      lastHeight = height;
    }

    if (frontier.timestamp >= ptlc.expirationTime) {
      if (ptlc.timeLocked == address) {
        print('Ptlc id ${red(ptlc.id.toString())} expired');
        print('  Reclaiming ptlc id ${red(ptlc.id.toString())} now... ');
        await send(znnClient.embedded.ptlc.reclaim(id));
        print('Done');
        return;
      }
    }
  }
}

Future<void> _message() async {
  if (args.length != 4) {
    print('Incorrect number of arguments. Expected:');
    print('ptlc.message id destination pointType');
    return;
  }

  final id = parseHash(args[1]);
  final destination = parseAddress(args[2]);
  final pointType = int.tryParse(args[3]);
  if (pointType == null || !ptlcPointLockSizes.containsKey(pointType)) {
    print('${red('Error!')} point type ${args[3]} is not supported');
    return;
  }
  final chainIdentifier = (await _frontier()).chainIdentifier;
  print('Chain identifier: $chainIdentifier');
  print(
      'Unlock message: ${green(hex.encode(PtlcApi.unlockMessage(chainIdentifier, pointType, id, destination)))}');
}

Future<void> _sign() async {
  if (args.length < 4 || args.length > 5) {
    print('Incorrect number of arguments. Expected:');
    print('ptlc.sign id destination secretKey [pointType]');
    print('  pointType 0 signs with Ed25519, 1 with BIP-340 (default)');
    return;
  }

  final id = parseHash(args[1]);
  final destination = parseAddress(args[2]);
  final secretKey = _hex(args[3], 'secretKey', 32);
  final pointType =
      args.length == 5 ? int.tryParse(args[4]) : ptlcPointTypeBip340;
  if (pointType != ptlcPointTypeEd25519 && pointType != ptlcPointTypeBip340) {
    print('${red('Error!')} point type must be 0 or 1');
    return;
  }

  final message = PtlcApi.unlockMessage(
      (await _frontier()).chainIdentifier, pointType!, id, destination);
  List<int> publicKey;
  List<int> signature;
  if (pointType == ptlcPointTypeEd25519) {
    publicKey = await Crypto.getPublicKey(secretKey);
    signature = await Crypto.sign(message, secretKey, publicKey);
  } else {
    if (Secp256k1.parseScalar(secretKey) == null) {
      print('${red('Error!')} secretKey is not a valid secp256k1 scalar');
      return;
    }
    publicKey = Bip340.publicKey(secretKey);
    signature = Bip340.sign(secretKey, message, _randomBytes(32));
  }
  print('Point lock: ${hex.encode(publicKey)}');
  print('Witness: ${green(hex.encode(signature))}');
}

void _keygen() {
  BigInt? secret;
  List<int> bytes = [];
  while (secret == null) {
    bytes = _randomBytes(32);
    secret = Secp256k1.parseScalar(bytes);
  }
  print('Secret: ${green(hex.encode(bytes))}');
  print('Point (point type 2): ${hex.encode(Secp256k1.scalarToPoint(secret))}');
  print('Key (point type 1): ${hex.encode(Bip340.publicKey(bytes))}');
}

void _point() {
  if (args.length != 2) {
    print('Incorrect number of arguments. Expected:');
    print('ptlc.point secret');
    return;
  }

  final secret = _scalar(args[1], 'secret');
  print('Point (point type 2): ${hex.encode(Secp256k1.scalarToPoint(secret))}');
  print(
      'Key (point type 1): ${hex.encode(Bip340.publicKey(Secp256k1.scalarToBytes(secret)))}');
}

void _tweak() {
  if (args.length != 3) {
    print('Incorrect number of arguments. Expected:');
    print('ptlc.tweak point tweak');
    return;
  }

  final point = _hex(args[1], 'point', 33);
  if (Secp256k1.parseCompressed(point) == null) {
    print('${red('Error!')} point is not a valid compressed secp256k1 point');
    return;
  }
  final tweak = _scalar(args[2], 'tweak');
  try {
    print(
        'Tweaked point: ${green(hex.encode(Secp256k1.tweakPoint(point, tweak)))}');
  } catch (e) {
    print('${red('Error!')} $e');
  }
}

void _tweakSecret() {
  if (args.length != 3) {
    print('Incorrect number of arguments. Expected:');
    print('ptlc.tweakSecret secret tweak');
    return;
  }

  final tweaked = Secp256k1.tweakScalar(
      _scalar(args[1], 'secret'), _scalar(args[2], 'tweak'));
  if (tweaked == BigInt.zero) {
    print('${red('Error!')} the tweak cancels the secret');
    return;
  }
  print(
      'Tweaked secret: ${green(hex.encode(Secp256k1.scalarToBytes(tweaked)))}');
  print('Tweaked point: ${hex.encode(Secp256k1.scalarToPoint(tweaked))}');
}

void _adaptorSign() {
  if (args.length != 4) {
    print('Incorrect number of arguments. Expected:');
    print('ptlc.adaptorSign secretKey message adaptorPoint');
    return;
  }

  final secretKey = _hex(args[1], 'secretKey', 32);
  if (Secp256k1.parseScalar(secretKey) == null) {
    print('${red('Error!')} secretKey is not a valid secp256k1 scalar');
    return;
  }
  final message = _hex(args[2], 'message');
  final adaptor = _hex(args[3], 'adaptorPoint', 33);
  if (Secp256k1.parseCompressed(adaptor) == null) {
    print(
        '${red('Error!')} adaptorPoint is not a valid compressed secp256k1 point');
    return;
  }
  final presig =
      Bip340.adaptorSign(secretKey, message, adaptor, _randomBytes(32));
  print('Public key: ${hex.encode(Bip340.publicKey(secretKey))}');
  print('Pre-signature: ${green(hex.encode(presig))}');
}

void _adaptorVerify() {
  if (args.length != 5) {
    print('Incorrect number of arguments. Expected:');
    print('ptlc.adaptorVerify publicKey message adaptorPoint preSignature');
    return;
  }

  final valid = Bip340.adaptorVerify(
      _hex(args[1], 'publicKey', 32),
      _hex(args[2], 'message'),
      _hex(args[3], 'adaptorPoint', 33),
      _hex(args[4], 'preSignature', 65));
  print(valid
      ? 'The pre-signature is ${green('valid')}'
      : 'The pre-signature is ${red('invalid')}');
  if (!valid) {
    exit(-1);
  }
}

void _adaptorComplete() {
  if (args.length != 3) {
    print('Incorrect number of arguments. Expected:');
    print('ptlc.adaptorComplete preSignature secret');
    return;
  }

  final presig = _hex(args[1], 'preSignature', 65);
  final secret = _scalar(args[2], 'secret');
  try {
    print(
        'Signature: ${green(hex.encode(Bip340.adaptorComplete(presig, secret)))}');
  } catch (e) {
    print('${red('Error!')} $e');
  }
}

void _adaptorExtract() {
  if (args.length != 3) {
    print('Incorrect number of arguments. Expected:');
    print('ptlc.adaptorExtract preSignature signature');
    return;
  }

  final presig = _hex(args[1], 'preSignature', 65);
  final signature = _hex(args[2], 'signature', 64);
  try {
    final secret = Bip340.adaptorExtract(presig, signature);
    print('Secret: ${green(hex.encode(Secp256k1.scalarToBytes(secret)))}');
    print('Point: ${hex.encode(Secp256k1.scalarToPoint(secret))}');
  } catch (e) {
    print('${red('Error!')} $e');
  }
}
