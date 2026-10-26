import 'package:test/test.dart';
import 'package:znn_cli_dart/lib.dart';
import 'package:znn_sdk_dart/znn_sdk_dart.dart';

PtlcInfo entry(int expirationTime) => PtlcInfo(
    id: Hash.digest([1]),
    timeLocked: emptyAddress,
    tokenStandard: znnZts,
    amount: BigInt.one,
    expirationTime: expirationTime,
    pointType: ptlcPointTypeBip340,
    pointLock: List.filled(32, 0),
    destination: emptyAddress);

void main() {
  const commands = [
    'ptlc.create',
    'ptlc.unlock',
    'ptlc.proxyUnlock',
    'ptlc.reclaim',
    'ptlc.get',
    'ptlc.inspect',
    'ptlc.monitor',
    'ptlc.message',
    'ptlc.sign',
    'ptlc.keygen',
    'ptlc.point',
    'ptlc.tweak',
    'ptlc.tweakSecret',
    'ptlc.adaptorSign',
    'ptlc.adaptorVerify',
    'ptlc.adaptorComplete',
    'ptlc.adaptorExtract',
    'ptlc.createWithReclaimLock',
    'ptlc.reclaimMessage',
    'ptlc.signReclaim',
  ];
  const offline = [
    'ptlc.keygen',
    'ptlc.point',
    'ptlc.tweak',
    'ptlc.tweakSecret',
    'ptlc.adaptorSign',
    'ptlc.adaptorVerify',
    'ptlc.adaptorComplete',
    'ptlc.adaptorExtract',
    'ptlc.signReclaim',
  ];
  const withWallet = [
    'ptlc.create',
    'ptlc.unlock',
    'ptlc.proxyUnlock',
    'ptlc.reclaim',
    'ptlc.monitor',
    'ptlc.createWithReclaimLock',
  ];

  group('commands', () {
    test('every ptlc command is registered once', () {
      for (final command in commands) {
        final lists = [commandsWithWallet, commandsWithoutWallet]
            .where((list) => list.contains(command));
        expect(lists.length, 1, reason: command);
      }
    });

    test('contract calls need a wallet', () {
      for (final command in withWallet) {
        expect(commandsWithWallet, contains(command));
      }
    });

    test('key and adaptor commands need no node', () {
      for (final command in offline) {
        expect(commandsWithoutConnection, contains(command));
        expect(commandsWithoutWallet, contains(command));
      }
      for (final command in commands.where((c) => !offline.contains(c))) {
        expect(commandsWithoutConnection, isNot(contains(command)));
      }
    });

    test('htlc commands are unchanged', () {
      for (final command in [
        'htlc.create',
        'htlc.unlock',
        'htlc.reclaim',
        'htlc.denyProxy',
        'htlc.allowProxy',
        'htlc.monitor'
      ]) {
        expect(commandsWithWallet, contains(command));
      }
      for (final command in [
        'htlc.get',
        'htlc.inspect',
        'htlc.getProxyStatus'
      ]) {
        expect(commandsWithoutWallet, contains(command));
      }
    });
  });

  group('ptlcPointTypeName', () {
    test('names every point type', () {
      expect(ptlcPointTypeName(ptlcPointTypeEd25519), 'Ed25519 key');
      expect(ptlcPointTypeName(ptlcPointTypeBip340), 'BIP-340 key');
      expect(ptlcPointTypeName(ptlcPointTypeSecp256k1Point), 'secp256k1 point');
      expect(ptlcPointTypeName(3), 'unknown (3)');
    });
  });

  group('ptlcRevealProblem', () {
    test('refuses an expired entry', () {
      expect(ptlcRevealProblem(entry(1000), 1000), contains('expired'));
      expect(ptlcRevealProblem(entry(1000), 2000), contains('expired'));
    });

    test('refuses an entry too close to its expiry', () {
      expect(ptlcRevealProblem(entry(1000), 1000 - ptlcRevealMargin + 1),
          contains('left'));
    });

    test('takes an entry with time to spare', () {
      expect(ptlcRevealProblem(entry(1000), 1000 - ptlcRevealMargin), isNull);
      expect(ptlcRevealProblem(entry(100000), 0), isNull);
    });
  });

  group('ptlcReclaimExpirationProblem', () {
    test('needs time for the create to be confirmed', () {
      expect(ptlcReclaimExpirationProblem(1000, 1000), isNotNull);
      expect(ptlcReclaimExpirationProblem(1000 + ptlcRevealMargin - 1, 1000),
          isNotNull);
      expect(ptlcReclaimExpirationProblem(1000 + ptlcRevealMargin, 1000),
          isNull);
    });

    test('caps the time lock', () {
      final max = ptlcTimelockMaxHours * 3600;
      expect(ptlcReclaimExpirationProblem(1000 + max, 1000), isNull);
      expect(ptlcReclaimExpirationProblem(1001 + max, 1000), isNotNull);
    });
  });

  group('ptlcReclaimProofProblem', () {
    final terms = PtlcInfo(
        id: emptyHash,
        timeLocked: pillarAddress,
        tokenStandard: znnZts,
        amount: BigInt.from(100000000),
        expirationTime: 1700000000,
        pointType: ptlcPointTypeBip340,
        pointLock: Bip340.publicKey(Bip340.sha256([40])),
        destination: emptyAddress);
    final key = Bip340.sha256([41]);
    final lock = Bip340.publicKey(key);
    final message = PtlcApi.reclaimMessageOf(69, ptlcPointTypeBip340, terms);
    final secret = Secp256k1.parseScalar(Bip340.sha256([42]))!;
    final adaptor = Secp256k1.scalarToPoint(secret);
    final preSignature =
        Bip340.adaptorSign(key, message, adaptor, Bip340.sha256([43]));

    test('takes a signature that verifies for the terms', () async {
      final signature = Bip340.sign(key, message, Bip340.sha256([44]));
      expect(
          await ptlcReclaimProofProblem(
              69, terms, ptlcPointTypeBip340, lock, signature, null),
          isNull);
      expect(
          await ptlcReclaimProofProblem(
              70, terms, ptlcPointTypeBip340, lock, signature, null),
          contains('does not verify'));
      expect(
          await ptlcReclaimProofProblem(
              69, terms, ptlcPointTypeBip340, lock, signature, adaptor),
          isNotNull);
    });

    test('takes a pre-signature with its adaptor point', () async {
      expect(
          await ptlcReclaimProofProblem(
              69, terms, ptlcPointTypeBip340, lock, preSignature, adaptor),
          isNull);
      expect(
          await ptlcReclaimProofProblem(
              69, terms, ptlcPointTypeBip340, lock, preSignature, null),
          contains('adaptor point'));
      expect(
          await ptlcReclaimProofProblem(69, terms, ptlcPointTypeBip340, lock,
              preSignature, Secp256k1.scalarToPoint(BigInt.from(5))),
          contains('does not verify'));
      final edKey = await Crypto.getPublicKey(key);
      expect(
          await ptlcReclaimProofProblem(
              69, terms, ptlcPointTypeEd25519, edKey, preSignature, adaptor),
          contains('BIP-340'));
    });

    test('refuses anything else', () async {
      expect(
          await ptlcReclaimProofProblem(
              69, terms, ptlcPointTypeBip340, lock, List.filled(32, 1), null),
          isNotNull);
      expect(
          await ptlcReclaimProofProblem(69, terms, ptlcPointTypeBip340, lock,
              preSignature.sublist(0, 64), null),
          contains('does not verify'));
    });
  });

  group('ptlcCallAccepted', () {
    test('reads the status of a contract receive block', () {
      expect(ptlcCallAccepted([0, 0, 0, 0, 0, 0, 0, 1]), isTrue);
      expect(ptlcCallAccepted([0, 0, 0, 0, 0, 0, 0, 2]), isFalse);
      expect(ptlcCallAccepted([0, 0, 0, 0, 0, 0, 0, 0]), isFalse);
      expect(ptlcCallAccepted([1]), isFalse);
      expect(ptlcCallAccepted([]), isFalse);
      expect(ptlcCallAccepted(null), isFalse);
    });
  });

  group('ptlcFunction', () {
    final api = PtlcApi();
    final id = Hash.digest([2]);
    final token = Token('Zenon', 'ZNN', 'zenon.network', BigInt.zero, 8,
        emptyAddress, znnZts, BigInt.zero, true, true, true);

    test('finds each contract method', () {
      final calls = {
        'Create': api
            .create(token, BigInt.one, 1700000000, ptlcPointTypeBip340,
                List.filled(32, 1), emptyAddress)
            .data,
        'Reclaim': api.reclaim(id).data,
        'Unlock': api.unlock(id, List.filled(64, 2)).data,
        'ProxyUnlock':
            api.proxyUnlock(id, pillarAddress, List.filled(32, 3)).data,
        'CreateWithReclaimLock': api
            .createWithReclaimLock(
                token,
                BigInt.one,
                1700000000,
                ptlcPointTypeBip340,
                List.filled(32, 1),
                emptyAddress,
                ptlcPointTypeBip340,
                List.filled(32, 4))
            .data,
        'ReclaimWithSignature':
            api.reclaimWithSignature(id, List.filled(64, 5)).data,
      };
      expect(calls.keys.toSet(),
          Definitions.ptlc.entries.map((e) => e.name).toSet());
      calls.forEach((name, data) {
        final f = ptlcFunction(data);
        expect(f, isNotNull, reason: name);
        expect(f!.name, name);
        expect(f.decode(data)[0].toString(),
            name.startsWith('Create') ? '1700000000' : id.toString());
      });
    });

    test('ignores data that is no ptlc call', () {
      expect(ptlcFunction([]), isNull);
      expect(ptlcFunction([1, 2, 3]), isNull);
      expect(
          ptlcFunction(Definitions.htlc.encodeFunction('DenyProxyUnlock', [])),
          isNull);
    });
  });
}
