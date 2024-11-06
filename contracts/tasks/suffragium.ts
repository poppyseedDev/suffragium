import { task } from "hardhat/config";
import type { TaskArguments } from "hardhat/types";

// Suffragium on Zama devnet: 0xAa6f7cA062d6575310057BbcCc24F4A1894E28eB

task("Suffragium:deploy")
  .addOptionalParam("verifier", "SP1 verifier address", "0x0000000000000000000000000000000000000000")
  .addOptionalParam(
    "programVKey",
    "SP1 program verification key",
    "0xa4896a3f93bf4bf58378e579f3cf193bb4af1022af7d2089f37d8bae7157b85f",
  ) //keccak256("random")
  .addOptionalParam(
    "emailPublicKeyHash",
    "Public key used to sign the email",
    "0x8b39002be4c8b153702a149047be2d0128ae34ddf04e34e6f1a29d1977add933",
  ) //keccak256("emailPublicKeyHash")
  .addOptionalParam(
    "fromDomainHash",
    "Email from domain",
    "0xb87aa5a74bac2260f7284fb359a8c607d4302ddfc24e406457e14751042a20d5",
  ) // keccak256("from@mail.com"));
  .setAction(async function (_taskArguments: TaskArguments, { ethers }) {
    const SuffragiumFactory = await ethers.getContractFactory("Suffragium");
    const suffragium = await SuffragiumFactory.deploy(
      _taskArguments.verifer,
      _taskArguments.programVKey,
      _taskArguments.emailPublicKeyHash,
      _taskArguments.fromDomainHash,
    );
    await suffragium.waitForDeployment();
    console.log("Suffragium deployed to: ", await suffragium.getAddress());
  });

task("Suffragium:createVote")
  .addParam("endBlock", "Block at which the vote ends")
  .addParam("minQuorum", "Minimum quorum", "500000000000000000") // 50%
  .addParam("description", "Vote description")
  .addParam("suffragium", "Suffragium contract address")
  .setAction(async function (_taskArguments: TaskArguments, { ethers }) {
    const SuffragiumFactory = await ethers.getContractFactory("Suffragium");
    const suffragium = await SuffragiumFactory.attach(_taskArguments.suffragium);
    await suffragium.createVote(_taskArguments.endBlock, _taskArguments.minQuorum, _taskArguments.description);
    console.log("Vote created");
  });

task("Suffragium:requestRevealVote")
  .addParam("voteId", "Vote id")
  .addParam("suffragium", "Suffragium contract address")
  .setAction(async function (_taskArguments: TaskArguments, { ethers }) {
    const SuffragiumFactory = await ethers.getContractFactory("Suffragium");
    const suffragium = await SuffragiumFactory.attach(_taskArguments.suffragium);
    await suffragium.requestRevealVote(_taskArguments.voteId);
    console.log("Request to reveal the vote sent");
  });
