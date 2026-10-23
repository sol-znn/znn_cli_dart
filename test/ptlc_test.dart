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
  ];
  const withWallet = [
    'ptlc.create',
    'ptlc.unlock',
    'ptlc.proxyUnlock',
    'ptlc.reclaim',
    'ptlc.monitor',
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
      };
      calls.forEach((name, data) {
        final f = ptlcFunction(data);
        expect(f, isNotNull, reason: name);
        expect(f!.name, name);
        expect(f.decode(data)[0].toString(),
            name == 'Create' ? '1700000000' : id.toString());
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
