import "reflect-metadata";
import { TestingAppChain } from "@proto-kit/sdk";
import { SpyMaster, Agent, AgentId, Message, SecurityCode } from "./SpyMaster";
import { Field, PrivateKey, MerkleMap, Poseidon, Bool, UInt64 } from "o1js";
import { Balances } from "./Balances";

describe("SpyMaster", () => {
  let appChain: TestingAppChain<{
    SpyMaster: typeof SpyMaster;
    Balances: typeof Balances;
  }>;

  let spymaster: SpyMaster;
  let balances: Balances;

  const aliceKey = PrivateKey.random();
  const alice = aliceKey.toPublicKey();

  const map = new MerkleMap();
  const key = Poseidon.hash(alice.toFields());
  map.set(key, Bool(true).toField());

  beforeAll(async () => {
    appChain = TestingAppChain.fromRuntime({
      modules: {
        SpyMaster: SpyMaster,
        Balances: Balances,
      },
      config: {
        SpyMaster: {},
        Balances: {},
      },
    });

    appChain.setSigner(aliceKey);

    await appChain.start();

    spymaster = appChain.runtime.resolve("SpyMaster");
    balances = appChain.runtime.resolve("Balances");
  });

  it("should add an agent", async () => {
    const tx = appChain.transaction(alice, () => {
      spymaster.addAgent(
        AgentId.from(0),
        new SecurityCode({ char0: new Field(97), char1: new Field(98) }),
      );
    });
    await tx.sign();
    await tx.send();
    await appChain.produceBlock();

    const agent = await appChain.query.runtime.SpyMaster.agents.get(
      AgentId.from(0),
    );
    expect(agent).toEqual(
      new Agent({
        agentId: AgentId.from(0),
        lastMessage: UInt64.from(0),
        securityCode: new SecurityCode({
          char0: new Field(97),
          char1: new Field(98),
        }),
      }),
    );
  });

  it("should process a message", async () => {
    const messageStr = "0123456789ab";
    const asciiFields = [];
    for (var i = 0; i < messageStr.length; i++) {
      asciiFields.push(Field(messageStr.charCodeAt(i)));
    }
    const message = new Message({
      messageNumber: UInt64.from(1),
      agentId: AgentId.from(0),
      body: asciiFields,
      securityCode: new SecurityCode({
        char0: new Field(97),
        char1: new Field(98),
      }),
    });
    const tx = appChain.transaction(alice, () => {
      spymaster.processMessage(message);
    });

    await tx.sign();
    await tx.send();

    let block = await appChain.produceBlock();

    expect(block).toBeTruthy();
    expect(block?.txs[0]?.status).toBeTruthy();

    const agent = await appChain.query.runtime.SpyMaster.agents.get(
      AgentId.from(0),
    );

    if (agent) expect(agent.lastMessage).toEqual(UInt64.from(1));
  });
});
