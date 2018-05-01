/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package exercício11;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.channels.FileChannel;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 *
 * @author jan
 */
public class Exercício11 {

    private static SecretKey chaveMestre;
    private static String chaveMestreString;
    private static String sal = "a0b7a99de04a63b464752d7787abe186";
    private static int iteracoes = 10000;
    private static File chaveiro = null;
    
    //Sal utilizado para derivar as chaves e os Ivs utilizados para cifrar as chaves 
    // e os Ivs do HMac do nome e do GCM da chave e do Iv
    private static String salKeyNome = "881900f5d6e5cabca409675791601323";
    private static String salIvNome = "b4bc5635a2b6a701ab988c285503becb";
    private static String salKeyGcmKey = "fa0c1a321ca6192b57b6a07a20a172e9";
    private static String salIvGcmKey = "79daf2b0b79fa34253fa69590e2ed6a3";
    private static String salKeyGcmIv = "c9cd3a072b8952fad9e168de7320459c";
    private static String salIvGcmIv = "8f373d9016b46aa3433a047e0f982b69";
    
    
    public static void main(String[] args) throws Exception {
        
        Scanner input = new Scanner(System.in);
        System.out.println("---------------Bem vindo ao chaveiro---------------");
        System.out.println("");
        System.out.println("Insira a sua senha: ");
        String senha = input.nextLine();
        
        chaveMestre = generateDerivedKey(senha, sal, iteracoes);
        chaveMestreString = Hex.encodeHexString(chaveMestre.getEncoded());
        
        //Ler esse arquivo
        File file1 = new File("chaveiro.dat");
        file1.createNewFile();
        
        chaveiro = file1;
        
        FileInputStream fileInput = new FileInputStream(file1);
        //Verifica se é a primeira vez com o arquivo
        if(fileInput.available() == 0){
            iniciaChaveiro();
        }else{
            //Verifica se após decifrar, o arquivo está ok
            File file2 = new File("chaveiroMemoria.dat");
            file2.createNewFile();
            //Copia o conteúdo do chaveiro para um chaveiro auxiliar
            FileChannel in = new FileInputStream(file1).getChannel();
            FileChannel out = (new FileOutputStream(file2)).getChannel();
            in.transferTo(0, file1.length(), out);
            in.close();
            out.close();
            try {
                tentaDecifrarChaveiro(file2);
            } catch (Exception e) {
                System.out.println("Você não possui acesso ao chaveiro. Vá embora!!!");
                System.exit(0);
            }
            decifraChaveiro();
        }
        
        System.out.println("Sua chave mestre é: " + chaveMestreString);
        
        menuInicial();
        
        //No fim da aplicação deve sempre ser cifrado o chaveiro
        cifraChaveiro();
        
    }
    
    public static void iniciaChaveiro() throws Exception{
        
        ArrayList<ArrayList> conteudoChaveiro = new ArrayList();
        
        ArrayList<String> hMacNome = new ArrayList();
        //ArrayList<String> salKeyNome = new ArrayList();
        //ArrayList<String> salIvNome = new ArrayList();
        //Não precisa porque a hmacKey pode ser gerada a partir da keyNome
        //ArrayList<Key> hMacKeyNome = new ArrayList();
        
        //GCM da chave e do iv pois ambos são usados para cifrar e decifrar o arquivo
        //Tanto gcmChave quanto gcmIv devem estar cifrados pelo GCM
        //Por isso o salChave e salIV de cada um é guardado, para que a chave e o iv utilizado para
        // fazer o gcm da chave possam ser derivados e utilizados para decifrar o gcm da chave
        ArrayList<String> gcmChave = new ArrayList();
        //ArrayList<String> salChaveGcmChave = new ArrayList();
        //ArrayList<String> salIvGcmChave = new ArrayList();
        ArrayList<String> gcmIv = new ArrayList();
        //ArrayList<String> salChaveGcmIv = new ArrayList();
        //ArrayList<String> salIvGcmIv = new ArrayList();
        
        conteudoChaveiro.add(hMacNome);
        //Removido para usar um para todos
        //conteudoChaveiro.add(salKeyNome);
        //conteudoChaveiro.add(salIvNome);
        conteudoChaveiro.add(gcmChave);
        //conteudoChaveiro.add(salChaveGcmChave);
        //conteudoChaveiro.add(salIvGcmChave);
        conteudoChaveiro.add(gcmIv);
        //conteudoChaveiro.add(salChaveGcmIv);
        //conteudoChaveiro.add(salIvGcmIv);
        
        FileOutputStream fileOut = new FileOutputStream(chaveiro);
        ObjectOutputStream objOut = new ObjectOutputStream(fileOut);
        
        objOut.writeObject(conteudoChaveiro);
        
        objOut.close();
        
    }
    
    public static void menuInicial() throws Exception {
        
        Scanner input = new Scanner(System.in);
        
        System.out.println("");
        System.out.println("------------------Funcionalidades------------------");
        System.out.println("");
        System.out.println("Informe o número da função desejada: ");
        System.out.println("");
        System.out.println("1- Cifrar arquivo");
        System.out.println("2- Decifrar arquivo");
        System.out.println("3- Consultar");
        System.out.println("4- Remover");
        System.out.println("5- Atualizar");
        System.out.println("6- Sair");
        System.out.println("");
        String opcao = input.nextLine();
        
        switch(opcao){
            case "1":
                telaCifraArquivo();
                break;
            case "2":
                telaDecifraArquivo();
                break;
            case "3":
                telaConsulta();
                break;
            case "4":
                telaRemove();
                break;
            case "5":
                telaAtualiza();
                break;
            case "6":
                break;
        }
        
    }
    
    public static void telaCifraArquivo() throws Exception{
        
        Scanner input = new Scanner(System.in);

        System.out.println("---------------Cifragem de arquivo---------------");
        System.out.println("");
        System.out.println("Insira o caminho de diretório para o arquivo: ");
        String caminhoArquivo = input.nextLine();
        cifraArquivo(caminhoArquivo);
        
        menuInicial();

    }
    
    public static void telaDecifraArquivo() throws Exception{
        
        Scanner input = new Scanner(System.in);

        System.out.println("--------------Decifragem de arquivo--------------");
        System.out.println("");
        System.out.println("Insira o caminho de diretório para o arquivo: ");
        String caminhoArquivo = input.nextLine();
        decifraArquivo(caminhoArquivo);
        
        menuInicial();

    }
    
    public static void telaConsulta() throws Exception{
        
        Scanner input = new Scanner(System.in);

        System.out.println("--------------Consultar Registro--------------");
        System.out.println("");
        System.out.println("Insira o nome do arquivo: ");
        String nomeArquivo = input.nextLine();
        consultaRegistro(nomeArquivo);
        
        menuInicial();

    }
    
    public static void telaRemove() throws Exception{
        
        Scanner input = new Scanner(System.in);

        System.out.println("---------------Remover Registro---------------");
        System.out.println("");
        System.out.println("Insira o nome do arquivo: ");
        String nomeArquivo = input.nextLine();
        removeRegistro(nomeArquivo);
        
        menuInicial();

    }
    
    public static void telaAtualiza() throws Exception{
        
        Scanner input = new Scanner(System.in);

        System.out.println("--------------Atualiza Registro--------------");
        System.out.println("");
        System.out.println("Insira o nome do arquivo: ");
        String nomeArquivo = input.nextLine();
        atualizaRegistro(nomeArquivo);
        
        menuInicial();

    }
    
    public static SecretKey generateDerivedKey(String password, String salt, Integer iterations) {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), iterations, 128);
        SecretKeyFactory pbkdf2 = null;
        String derivedPass = null;
        try {
            pbkdf2 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            SecretKey sk = pbkdf2.generateSecret(spec);
            return sk;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    
    /*public void insereRegistro(String registro){
        
        try {

            //Gera o arquivo para armazenar o objeto
            FileOutputStream fos = new FileOutputStream("chaveiro.dat");

            //Classe responsavel por inserir os objetos
            ObjectOutputStream oos = new ObjectOutputStream(fos);

            oos.flush();

            oos.close();

            fos.flush();

            fos.close();

            System.out.println("Objeto gravado com sucesso!");

        } catch (Exception e) {

            e.printStackTrace();

        }
        
    }*/

    /*private static void leArquivo() {

        try {
            FileReader arq = new FileReader("/home/jan/Documentos/teste.txt");
            BufferedReader lerArq = new BufferedReader(arq);

            String linha = lerArq.readLine(); // lê a primeira linha
            // a variável "linha" recebe o valor "null" quando o processo
            // de repetição atingir o final do arquivo texto
            while (linha != null) {
                System.out.printf("%s\n", linha);

                linha = lerArq.readLine(); // lê da segunda até a última linha
            }

            arq.close();
        } catch (IOException e) {
            System.err.printf("Erro na abertura do arquivo: %s.\n",
                    e.getMessage());
        }
        
    }*/
    
    public static String geraSal() {
        
        try{
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        //SecureRandom sr = new SecureRandom();
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        return Hex.encodeHexString(salt);
        }catch(NoSuchAlgorithmException e){
            System.out.println(e.getMessage());
        }
        return null;
    }
    
    public static byte[] geraIV()throws Exception{
        byte[] iv = new byte[16];
        SecureRandom random = null;
        
        random = SecureRandom.getInstance("SHA1PRNG", "SUN");
        
        random.nextBytes(iv);
        return iv;
    }

    private static void cifraArquivo(String caminhoArquivo) throws Exception {

        
        int addProvider1 = Security.addProvider(new BouncyCastleProvider());
        
        File file = new File(caminhoArquivo);
        
        if(!file.exists()){
            System.out.println("");
            System.out.println("O caminho especificado não corresponde a um arquivo!");
        }else{
            
            KeyGenerator sKenGen = KeyGenerator.getInstance("AES");
            Key aesKey = sKenGen.generateKey();
            
            byte[] ivByte = geraIV();
            IvParameterSpec ivSpec = new IvParameterSpec(ivByte);

            //Leitura
            FileReader arquivoLer = new FileReader(file);
            BufferedReader lerArq = new BufferedReader(arquivoLer);

            StringBuilder sb = new StringBuilder();
            
            String linha = lerArq.readLine();
            sb.append(linha);

            while (linha != null) {
                linha = lerArq.readLine();
                
                if(linha != null){
                    sb.append(System.lineSeparator());
                    sb.append(linha);
                }
                
            }
            
            String texto = sb.toString();

            lerArq.close();
            
            byte[] conteudoArquivo = texto.getBytes();
            
            // Instanciando cipher
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
            
            //Cifra o texto
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);

            byte[] conteudoCifrado = new byte[cipher.getOutputSize(ivByte.length + conteudoArquivo.length)];

            int ctLength = cipher.update(ivByte, 0, ivByte.length, conteudoCifrado, 0);

            ctLength += cipher.update(conteudoArquivo, 0, conteudoArquivo.length, conteudoCifrado, ctLength);

            ctLength += cipher.doFinal(conteudoCifrado, ctLength);
            
            String cifradoString = new String(conteudoCifrado);
            //String contendo conteudo cifradoXXX
            
            //Escrita
            FileWriter arquivoEscrever = new FileWriter(file);
            BufferedWriter buffWrite = new BufferedWriter(arquivoEscrever);
            
            buffWrite.append(cifradoString);
        
            buffWrite.close();
            
            //Adiciona os dados no chaveiro
            incluiHMacNome(file);
            incluiGcmKeyIv(aesKey, ivSpec);
            
            
        }

    }
    
    private static String	digits = "0123456789abcdef";
    
    public static String toHex(byte[] data, int length)
    {
        StringBuffer	buf = new StringBuffer();
        
        for (int i = 0; i != length; i++)
        {
            int	v = data[i] & 0xff;
            
            buf.append(digits.charAt(v >> 4));
            buf.append(digits.charAt(v & 0xf));
        }
        
        return buf.toString();
    }
    
    public static String toHex(byte[] data)
    {
        return toHex(data, data.length);
    }

    private static void decifraArquivo(String caminhoArquivo) throws Exception{

        int addProvider = Security.addProvider(new BouncyCastleProvider());
        
        File file = new File(caminhoArquivo);
        
        if(!file.exists()){
            System.out.println("O caminho especificado não corresponde a um arquivo!");
        }else{
            
            String nomeArquivo = file.getName();
            
            int posicao = verificaNome(nomeArquivo);
            
            if(posicao == -1){
                System.out.println("O arquivo especificado não foi encontrado no chaveiro");
            }else{
                FileInputStream chaveiroInput = new FileInputStream(chaveiro);
                ObjectInputStream objInput = new ObjectInputStream(chaveiroInput);
                
                ArrayList<ArrayList> conteudoChaveiro = (ArrayList) objInput.readObject();
                
                objInput.close();
                
                String gcmKey = (String)conteudoChaveiro.get(1).get(posicao);
                String gcmIv = (String)conteudoChaveiro.get(2).get(posicao);
                byte[] gcmKeyByte = org.apache.commons.codec.binary.Hex.decodeHex(gcmKey.toCharArray());
                byte[] gcmIvByte = org.apache.commons.codec.binary.Hex.decodeHex(gcmIv.toCharArray());
                
                //gcmKey
                GCMBlockCipher gcmChave = new GCMBlockCipher(new AESEngine());
                
                SecretKey sk = generateDerivedKey(chaveMestreString, salKeyGcmKey, iteracoes);
                String chaveHex = Hex.encodeHexString(sk.getEncoded());
                byte[] chave = org.apache.commons.codec.binary.Hex.decodeHex(chaveHex.toCharArray());
                
                SecretKey si = generateDerivedKey(chaveMestreString, salIvGcmKey, iteracoes);
                String ivHex = Hex.encodeHexString(si.getEncoded());
                byte[] iv = org.apache.commons.codec.binary.Hex.decodeHex(ivHex.toCharArray());
                
                KeyParameter chave2 = new KeyParameter(chave);
                AEADParameters params = new AEADParameters(chave2, 64, iv);
                
                gcmChave.init(false, params);

                int outsize2 = gcmChave.getOutputSize(gcmKeyByte.length);
                byte[] chaveDecifradaByte = new byte[outsize2];
                int offOut2 = gcmChave.processBytes(gcmKeyByte, 0, gcmKeyByte.length, chaveDecifradaByte, 0);
                
                gcmChave.doFinal(chaveDecifradaByte, offOut2);
                
                //gcmIv
                GCMBlockCipher gcmIv2 = new GCMBlockCipher(new AESEngine());
                
                sk = generateDerivedKey(chaveMestreString, salKeyGcmIv, iteracoes);
                chaveHex = Hex.encodeHexString(sk.getEncoded());
                chave = org.apache.commons.codec.binary.Hex.decodeHex(chaveHex.toCharArray());
                
                si = generateDerivedKey(chaveMestreString, salIvGcmIv, iteracoes);
                ivHex = Hex.encodeHexString(si.getEncoded());
                iv = org.apache.commons.codec.binary.Hex.decodeHex(ivHex.toCharArray());
                
                chave2 = new KeyParameter(chave);
                params = new AEADParameters(chave2, 64, iv);
                
                gcmIv2.init(false, params);

                outsize2 = gcmIv2.getOutputSize(gcmIvByte.length);
                byte[] ivDecifradoByte = new byte[outsize2];
                offOut2 = gcmIv2.processBytes(gcmIvByte, 0, gcmIvByte.length, ivDecifradoByte, 0);
                gcmIv2.doFinal(ivDecifradoByte, offOut2);
                
                //chaveDecifradaByte e ivDecifradoByte
                Key chaveDecifrada = new SecretKeySpec(chaveDecifradaByte, "AES");
                IvParameterSpec ivDecifrado = new IvParameterSpec(ivDecifradoByte);
                
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
                
                cipher.init(Cipher.DECRYPT_MODE, chaveDecifrada, ivDecifrado);
                
                FileReader arquivoLer = new FileReader(file);
                BufferedReader lerArq = new BufferedReader(arquivoLer);
                
                //Arquivo cifrado só tem uma linha
                String textoCifrado = lerArq.readLine();
                byte[] textoCifradoByte = textoCifrado.getBytes();
                
                byte[] textoDecifradoByte = cipher.doFinal(textoCifradoByte);
                String textoDecifrado = new String(textoDecifradoByte);
                
                //Escrita
                FileWriter arquivoEscrever = new FileWriter(file);
                BufferedWriter buffWrite = new BufferedWriter(arquivoEscrever);

                buffWrite.append(textoDecifrado);

                buffWrite.close();
            
            /*
                cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);

                byte[] conteudoCifrado = new byte[cipher.getOutputSize(ivByte.length + conteudoArquivo.length)];

                int ctLength = cipher.update(ivByte, 0, ivByte.length, conteudoCifrado, 0);

                ctLength += cipher.update(conteudoArquivo, 0, conteudoArquivo.length, conteudoCifrado, ctLength);

                ctLength += cipher.doFinal(conteudoCifrado, ctLength);

                String cifradoString = new String(conteudoCifrado);
               */ 
            }
            
            
        }
        /*
        int addProvider = Security.addProvider(new BouncyCastleProvider());
        
        String nomeArquivo = file.getName();
        
        Key chaveGerada = generateDerivedKey(chaveMestreString, salKeyNome, iteracoes);
        String chaveHex = Hex.encodeHexString(chaveGerada.getEncoded());
        byte[] chaveByte = org.apache.commons.codec.binary.Hex.decodeHex(chaveHex.toCharArray());
        Key chave = new SecretKeySpec(chaveByte, "AES");
        Key chaveHMac = new SecretKeySpec(chave.getEncoded(), "HMacSHA256");
        
        Key ivGerado = generateDerivedKey(chaveMestreString, salIvNome, iteracoes);
        String ivHex = Hex.encodeHexString(ivGerado.getEncoded());
        byte[] ivByte = org.apache.commons.codec.binary.Hex.decodeHex(ivHex.toCharArray());
        IvParameterSpec ivSpec = new IvParameterSpec(ivByte);
        
        Mac hMac = Mac.getInstance("HMacSHA256");
        
        //teste
        KeyGenerator sKenGen = KeyGenerator.getInstance("AES");
        Key aesKey = sKenGen.generateKey();
        
        //Cipher cipher = Cipher.getInstance("AES/CTR/PKCS7Padding");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
        
        byte[] textoCifrado = new byte[cipher.getOutputSize(nomeArquivo.length() + hMac.getMacLength())];
        
        int ctLength = cipher.update(nomeArquivo.getBytes(), 0, nomeArquivo.length(), textoCifrado, 0);
        
        hMac.init(chaveHMac);
        hMac.update(nomeArquivo.getBytes());
        
        ctLength += cipher.doFinal(hMac.doFinal(), 0, hMac.getMacLength(), textoCifrado, ctLength);
        
        String textoCifradoHex = toHex(textoCifrado);
        
        FileInputStream chaveiroInput = new FileInputStream(chaveiro);
        ObjectInputStream objInput = new ObjectInputStream(chaveiroInput);
        
        ArrayList<ArrayList> conteudoChaveiro = (ArrayList)objInput.readObject();
        
        objInput.close();
        
        conteudoChaveiro.get(0).add(textoCifradoHex);
        
        FileOutputStream chaveiroOut = new FileOutputStream(chaveiro);
        ObjectOutputStream objOut = new ObjectOutputStream(chaveiroOut);
        
        objOut.writeObject(conteudoChaveiro);
        
        objOut.close();
        */
        
    }

    private static void consultaRegistro(String nomeArquivo) {

    }

    private static void removeRegistro(String nomeArquivo) {

    }

    private static void atualizaRegistro(String nomeArquivo) {

    }

    private static void cifraChaveiro() throws Exception {

        byte[] chave = org.apache.commons.codec.binary.Hex.decodeHex(chaveMestreString.toCharArray());
        
        SecretKey sk = generateDerivedKey(chaveMestreString, sal, iteracoes);
        String ivHex = Hex.encodeHexString(sk.getEncoded());
        byte[] iv = org.apache.commons.codec.binary.Hex.decodeHex(ivHex.toCharArray());
        
        FileInputStream fileInput = new FileInputStream(chaveiro);
        ObjectInputStream objInput = new ObjectInputStream(fileInput);
        
        ArrayList<ArrayList> objetoHex = (ArrayList<ArrayList>)objInput.readObject();
        byte[] conteudoByte = convertObjectToByteArray(objetoHex);
        objInput.close();
        
        GCMBlockCipher gcm = new GCMBlockCipher(new AESEngine());
        
        KeyParameter chave2 = new KeyParameter(chave);
        AEADParameters params = new AEADParameters(chave2, 64, iv);
        
        gcm.init(true, params);
        int outsize = gcm.getOutputSize(conteudoByte.length);
        byte[] outc = new byte[outsize];
        
        int lengthOutc = gcm.processBytes(conteudoByte, 0, conteudoByte.length, outc, 0);
        
        gcm.doFinal(outc, lengthOutc);
        
        FileOutputStream fileOut = new FileOutputStream(chaveiro);
        ObjectOutputStream objOut = new ObjectOutputStream(fileOut);
        
        objOut.writeObject(org.bouncycastle.util.encoders.Hex.toHexString(outc));
        
        objOut.close();
        
        System.out.println("Chaveiro cifrado = " + org.bouncycastle.util.encoders.Hex.toHexString(outc));
        
    }

    private static void decifraChaveiro() throws Exception {

        byte[] chave = org.apache.commons.codec.binary.Hex.decodeHex(chaveMestreString.toCharArray());
        
        SecretKey sk = generateDerivedKey(chaveMestreString, sal, iteracoes);
        String ivHex = Hex.encodeHexString(sk.getEncoded());
        byte[] iv = org.apache.commons.codec.binary.Hex.decodeHex(ivHex.toCharArray());
        
        FileInputStream fileInput = new FileInputStream(chaveiro);
        ObjectInputStream objInput = new ObjectInputStream(fileInput);
        
        String objetoHexa = (String)objInput.readObject();
        objInput.close();
        byte[] objetoByte = org.apache.commons.codec.binary.Hex.decodeHex(objetoHexa.toCharArray());
        
        GCMBlockCipher gcm = new GCMBlockCipher(new AESEngine());
        
        KeyParameter chave2 = new KeyParameter(chave);
        AEADParameters params = new AEADParameters(chave2, 64, iv);
        
        gcm.init(false, params);

        int outsize2 = gcm.getOutputSize(objetoByte.length);
        byte[] out2 = new byte[outsize2];
        int offOut2 = gcm.processBytes(objetoByte, 0, objetoByte.length, out2, 0);
        
        String textoDecifrado = "";
        try {  
            gcm.doFinal(out2, offOut2);           
            textoDecifrado = new String(out2);

        } catch (InvalidCipherTextException e) {
            System.err.println("Erro de decifragem: " + e.getMessage());
            //e.printStackTrace();
        }
        
        FileOutputStream fileOut = new FileOutputStream(chaveiro);
        ObjectOutputStream objOut = new ObjectOutputStream(fileOut);
        
        ArrayList<ArrayList> saida = (ArrayList<ArrayList>)convertByteArrayToObject(out2);
        
        objOut.writeObject(saida);
        
        objOut.close();
        
        
    }
    
    public static byte[] convertObjectToByteArray(Object object) {
        byte[] bytes = null;
        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(object);
            objectOutputStream.flush();
            objectOutputStream.close();
            byteArrayOutputStream.close();
            bytes = byteArrayOutputStream.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
        }
         
        return bytes;
    }
    
    public static Object convertByteArrayToObject(byte[] bytes) {
        Object object = null;
 
        try {
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
            ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
            object = objectInputStream.readObject();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
         
        return object;
    }

    private static void tentaDecifrarChaveiro(File file2) throws Exception {

        byte[] chave = org.apache.commons.codec.binary.Hex.decodeHex(chaveMestreString.toCharArray());
        
        SecretKey sk = generateDerivedKey(chaveMestreString, sal, iteracoes);
        String ivHex = Hex.encodeHexString(sk.getEncoded());
        byte[] iv = org.apache.commons.codec.binary.Hex.decodeHex(ivHex.toCharArray());
        
        FileInputStream fileInput = new FileInputStream(file2);
        ObjectInputStream objInput = new ObjectInputStream(fileInput);
        
        String objetoHexa = (String)objInput.readObject();
        objInput.close();
        byte[] objetoByte = org.apache.commons.codec.binary.Hex.decodeHex(objetoHexa.toCharArray());
        
        GCMBlockCipher gcm = new GCMBlockCipher(new AESEngine());
        
        KeyParameter chave2 = new KeyParameter(chave);
        AEADParameters params = new AEADParameters(chave2, 64, iv);
        
        gcm.init(false, params);

        int outsize2 = gcm.getOutputSize(objetoByte.length);
        byte[] out2 = new byte[outsize2];
        int offOut2 = gcm.processBytes(objetoByte, 0, objetoByte.length, out2, 0);
        
        String textoDecifrado = "";
          
        gcm.doFinal(out2, offOut2);           
        textoDecifrado = new String(out2);
        
    }

    private static void incluiHMacNome(File file) throws Exception {

        int addProvider = Security.addProvider(new BouncyCastleProvider());
        
        String nomeArquivo = file.getName();
        
        Key chaveGerada = generateDerivedKey(chaveMestreString, salKeyNome, iteracoes);
        String chaveHex = Hex.encodeHexString(chaveGerada.getEncoded());
        byte[] chaveByte = org.apache.commons.codec.binary.Hex.decodeHex(chaveHex.toCharArray());
        Key chaveHMac = new SecretKeySpec(chaveByte, "HMacSHA256");
        
        Mac hMac = Mac.getInstance("HMacSHA256");
        
        hMac.init(chaveHMac);
        hMac.update(nomeArquivo.getBytes());
        
        byte[] hMacNomeArquivo = hMac.doFinal();
        
        FileInputStream chaveiroInput = new FileInputStream(chaveiro);
        ObjectInputStream objInput = new ObjectInputStream(chaveiroInput);
        
        ArrayList<ArrayList> conteudoChaveiro = (ArrayList)objInput.readObject();
        
        objInput.close();
        
        conteudoChaveiro.get(0).add(toHex(hMacNomeArquivo));
        
        FileOutputStream chaveiroOut = new FileOutputStream(chaveiro);
        ObjectOutputStream objOut = new ObjectOutputStream(chaveiroOut);
        
        objOut.writeObject(conteudoChaveiro);
        
        objOut.close();
        /*
        Key chaveGerada = generateDerivedKey(chaveMestreString, salKeyNome, iteracoes);
        String chaveHex = Hex.encodeHexString(chaveGerada.getEncoded());
        byte[] chaveByte = org.apache.commons.codec.binary.Hex.decodeHex(chaveHex.toCharArray());
        Key chave = new SecretKeySpec(chaveByte, "AES");
        Key chaveHMac = new SecretKeySpec(chave.getEncoded(), "HMacSHA256");
        
        Key ivGerado = generateDerivedKey(chaveMestreString, salIvNome, iteracoes);
        String ivHex = Hex.encodeHexString(ivGerado.getEncoded());
        byte[] ivByte = org.apache.commons.codec.binary.Hex.decodeHex(ivHex.toCharArray());
        IvParameterSpec ivSpec = new IvParameterSpec(ivByte);
        
        Mac hMac = Mac.getInstance("HMacSHA256");
        
        //Cipher cipher = Cipher.getInstance("AES/CTR/PKCS7Padding");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
        cipher.init(Cipher.ENCRYPT_MODE, chave, ivSpec);
        
        byte[] textoCifrado = new byte[cipher.getOutputSize(nomeArquivo.length() + hMac.getMacLength())];
        
        int ctLength = cipher.update(nomeArquivo.getBytes(), 0, nomeArquivo.length(), textoCifrado, 0);
        
        hMac.init(chaveHMac);
        hMac.update(nomeArquivo.getBytes());
        
        ctLength += cipher.doFinal(hMac.doFinal(), 0, hMac.getMacLength(), textoCifrado, ctLength);
        
        String textoCifradoHex = toHex(textoCifrado);
        
        FileInputStream chaveiroInput = new FileInputStream(chaveiro);
        ObjectInputStream objInput = new ObjectInputStream(chaveiroInput);
        
        ArrayList<ArrayList> conteudoChaveiro = (ArrayList)objInput.readObject();
        
        objInput.close();
        
        conteudoChaveiro.get(0).add(textoCifradoHex);
        
        FileOutputStream chaveiroOut = new FileOutputStream(chaveiro);
        ObjectOutputStream objOut = new ObjectOutputStream(chaveiroOut);
        
        objOut.writeObject(conteudoChaveiro);
        
        objOut.close();
        */
    }

    private static void incluiGcmKeyIv(Key aesKey, IvParameterSpec ivSpec) throws Exception {
        
        String chaveParamHex = Hex.encodeHexString(aesKey.getEncoded());
        byte[] chavePlanaByte = org.apache.commons.codec.binary.Hex.decodeHex(chaveParamHex.toCharArray());
        
        byte[] ivPlanoByte = ivSpec.getIV();
        
        //Chave e IV da chave
        //Inicio
        SecretKey sk = generateDerivedKey(chaveMestreString, salKeyGcmKey, iteracoes);
        String chaveHex = Hex.encodeHexString(sk.getEncoded());
        byte[] chave = org.apache.commons.codec.binary.Hex.decodeHex(chaveHex.toCharArray());
        
        SecretKey si = generateDerivedKey(chaveMestreString, salIvGcmKey, iteracoes);
        String ivHex = Hex.encodeHexString(si.getEncoded());
        byte[] iv = org.apache.commons.codec.binary.Hex.decodeHex(ivHex.toCharArray());
        
        GCMBlockCipher gcmChave = new GCMBlockCipher(new AESEngine());
        
        KeyParameter chave2 = new KeyParameter(chave);
        AEADParameters params = new AEADParameters(chave2, 64, iv);
        
        gcmChave.init(true, params);
        int outsize = gcmChave.getOutputSize(chavePlanaByte.length);
        byte[] chaveCifrada = new byte[outsize];
        
        int lengthOutc = gcmChave.processBytes(chavePlanaByte, 0, chavePlanaByte.length, chaveCifrada, 0);
        
        gcmChave.doFinal(chaveCifrada, lengthOutc);
        
        
        //Fim
        
        //Chave e IV do IV
        //Inicio
        
        sk = generateDerivedKey(chaveMestreString, salKeyGcmIv, iteracoes);
        chaveHex = Hex.encodeHexString(sk.getEncoded());
        chave = org.apache.commons.codec.binary.Hex.decodeHex(chaveHex.toCharArray());
        
        si = generateDerivedKey(chaveMestreString, salIvGcmIv, iteracoes);
        ivHex = Hex.encodeHexString(si.getEncoded());
        iv = org.apache.commons.codec.binary.Hex.decodeHex(ivHex.toCharArray());
        
        GCMBlockCipher gcmIv = new GCMBlockCipher(new AESEngine());
        
        chave2 = new KeyParameter(chave);
        params = new AEADParameters(chave2, 64, iv);
        
        gcmIv.init(true, params);
        outsize = gcmIv.getOutputSize(ivPlanoByte.length);
        byte[] ivCifrado = new byte[outsize];
        
        lengthOutc = gcmIv.processBytes(ivPlanoByte, 0, ivPlanoByte.length, ivCifrado, 0);
        
        gcmIv.doFinal(ivCifrado, lengthOutc);
        
        //Fim
        
        //Adiciona ambos no chaveiro
        FileInputStream chaveiroInput = new FileInputStream(chaveiro);
        ObjectInputStream objInput = new ObjectInputStream(chaveiroInput);
        
        ArrayList<ArrayList> conteudoChaveiro = (ArrayList)objInput.readObject();
        
        objInput.close();
        
        conteudoChaveiro.get(1).add(toHex(chaveCifrada));
        conteudoChaveiro.get(2).add(toHex(ivCifrado));
        
        FileOutputStream chaveiroOut = new FileOutputStream(chaveiro);
        ObjectOutputStream objOut = new ObjectOutputStream(chaveiroOut);
        
        objOut.writeObject(conteudoChaveiro);
        
        objOut.close();
        
    }

    private static int verificaNome(String nomeArquivo) throws Exception{

        Key chaveGerada = generateDerivedKey(chaveMestreString, salKeyNome, iteracoes);
        String chaveHex = Hex.encodeHexString(chaveGerada.getEncoded());
        byte[] chaveByte = org.apache.commons.codec.binary.Hex.decodeHex(chaveHex.toCharArray());
        Key chaveHMac = new SecretKeySpec(chaveByte, "HMacSHA256");
        
        Key ivGerado = generateDerivedKey(chaveMestreString, salIvNome, iteracoes);
        String ivHex = Hex.encodeHexString(ivGerado.getEncoded());
        byte[] ivByte = org.apache.commons.codec.binary.Hex.decodeHex(ivHex.toCharArray());
        IvParameterSpec ivSpec = new IvParameterSpec(ivByte);
        
        Mac hMac = Mac.getInstance("HMacSHA256");
        
        hMac.init(chaveHMac);
        hMac.update(nomeArquivo.getBytes());
        
        byte[] hMacNomeArquivo = hMac.doFinal();
        
        FileInputStream chaveiroInput = new FileInputStream(chaveiro);
        ObjectInputStream objInput = new ObjectInputStream(chaveiroInput);
        
        ArrayList<ArrayList> conteudoChaveiro = (ArrayList)objInput.readObject();
        
        objInput.close();
        
        ArrayList<String> hMacArquivoChaveiro = conteudoChaveiro.get(0);
        int posicao = -1;
        for (int i = 0; i < hMacArquivoChaveiro.size(); i++) {
            String arquivo = hMacArquivoChaveiro.get(i);
            byte[] arquivoByte = org.apache.commons.codec.binary.Hex.decodeHex(arquivo.toCharArray());
            if(MessageDigest.isEqual(arquivoByte, hMacNomeArquivo)){
                posicao = i;
            }
        }
        
        return posicao;
        
        //MessageDigest.isEqual(hMac.doFinal(), messageMac));
        /*
        Key chaveGerada = generateDerivedKey(chaveMestreString, salKeyNome, iteracoes);
        String chaveHex = Hex.encodeHexString(chaveGerada.getEncoded());
        byte[] chaveByte = org.apache.commons.codec.binary.Hex.decodeHex(chaveHex.toCharArray());
        Key chaveHMac = new SecretKeySpec(chaveByte, "HMacSHA256");
        
        Mac hMac = Mac.getInstance("HMacSHA256");
        
        hMac.init(chaveHMac);
        hMac.update(nomeArquivo.getBytes());
        
        byte[] hMacNomeArquivo = hMac.doFinal();
        
        FileInputStream chaveiroInput = new FileInputStream(chaveiro);
        ObjectInputStream objInput = new ObjectInputStream(chaveiroInput);
        
        ArrayList<ArrayList> conteudoChaveiro = (ArrayList)objInput.readObject();
        
        objInput.close();
        
        conteudoChaveiro.get(0).add(toHex(hMacNomeArquivo));
        
        FileOutputStream chaveiroOut = new FileOutputStream(chaveiro);
        ObjectOutputStream objOut = new ObjectOutputStream(chaveiroOut);
        
        objOut.writeObject(conteudoChaveiro);
        
        objOut.close();
        */
        
        
    }
    
    
}
