package com.example.chain33test;

import cn.chain33.javasdk.client.Account;
import cn.chain33.javasdk.client.RpcClient;
import cn.chain33.javasdk.model.AccountInfo;
import cn.chain33.javasdk.model.TransferBalanceRequest;
import cn.chain33.javasdk.model.rpcresult.AccountResult;
import cn.chain33.javasdk.utils.TransactionUtil;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.IOException;
import java.util.List;

@SpringBootTest
class Chain33TestApplicationTests {
    RpcClient client = new RpcClient("47.96.16.13", 8801);

    @Test
    void contextLoads() throws IOException {
        System.out.println(client.isSync());
    }

    // 新建账户
    @Test
    void testNewAccountLocal() throws IOException {


        Account account = new Account();
        AccountInfo accountInfo = account.newAccountLocal("test","123456","/Users/chenqipeng/programming/code/chain33-test/accounts");
        System.out.println("privateKey is:" + accountInfo.getPrivateKey());
        System.out.println("publicKey is:" + accountInfo.getPublicKey());
        System.out.println("Address is:" + accountInfo.getAddress());

//        "cqp","123456"
//        privateKey is:22ad426e23d6c43280838690ed6d92e0efec0815505bd0495db31882cb8fff1a
//        publicKey is:02bbc936c860477df57df9eba0711bf8286899381e06c6da6f955752424a625f2e
//        Address is:16FycAptPfPvnq5eknYsdjcTKgdZXfwpDa

//        "test","123456"
//        privateKey is:1c9d7004057116a0c05d3caa4e6cadf9991af9fe4b6c711ac7aad023da525fb0
//        publicKey is:024ac23230bb95fad9fb951c47b8c8365da50eed1c94e77c89cea35d5bf8cd995c
//        Address is:1Gg7ZJh7jaHHTSQMYJHuskswGbajVYqwUg
    }

    // 验证地址
    @Test
    void testValidAddress() throws IOException {
        String address = "1wkG8kjtzGzdYiEhUxmysbpWToFtCssiJ";
        boolean validAddressResult = TransactionUtil.validAddress(address);
        System.out.printf("validate result is:%s", validAddressResult);
    }

    // 转账
    @Test
    void testTransaction(){
        TransferBalanceRequest transferBalanceRequest = new TransferBalanceRequest();
        transferBalanceRequest.setNote("转账说明:测试转账功能");
        // 转主积分的情况下，默认填""
        transferBalanceRequest.setCoinToken("");
        // 转账数量 ， 以下代表转1个积分
        transferBalanceRequest.setAmount(1 * 100000000L);
        // 转到的地址
        transferBalanceRequest.setTo("1wkG8kjtzGzdYiEhUxmysbpWToFtCssiJ");
    }
}