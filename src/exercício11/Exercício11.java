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
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.nio.channels.FileChannel;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

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
    private static ArrayList<ArrayList> conteudoChaveiro = null;
    
    
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
            iniciaChaveiro(file1);
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
    
    public static void iniciaChaveiro(File arquivoChaveiro) throws Exception{
        
        conteudoChaveiro = new ArrayList();
        
        ArrayList<String> nomeArquivo = new ArrayList();
        ArrayList<String> salNome = new ArrayList();
        ArrayList<String> chaveArquivo = new ArrayList();
        ArrayList<String> salChave = new ArrayList();
        
        conteudoChaveiro.add(nomeArquivo);
        conteudoChaveiro.add(salNome);
        conteudoChaveiro.add(chaveArquivo);
        conteudoChaveiro.add(salChave);
        
        FileOutputStream fileOut = new FileOutputStream(arquivoChaveiro);
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
        
        int addProvider = Security.addProvider(new BouncyCastleFipsProvider());

        if (Security.getProvider("BCFIPS") == null) {
            System.out.println("Bouncy Castle provider NAO disponivel");
        } else {
            System.out.println("Bouncy Castle provider esta disponivel");
        }
        
        String salCifragemArquivo = geraSal();
        SecretKey chaveCifragemArquivo = generateDerivedKey(chaveMestreString, salCifragemArquivo, iteracoes);
        byte[] ivCifragemArquivo = geraIV();
        IvParameterSpec ivSpec = new IvParameterSpec(ivCifragemArquivo);
        
        try {
            FileReader arquivoLer = new FileReader(caminhoArquivo);
            BufferedReader lerArq = new BufferedReader(arquivoLer);
            
            FileWriter arquivoEscrever = new FileWriter(caminhoArquivo, true);
            BufferedWriter buffWrite = new BufferedWriter(arquivoEscrever);

            // lê a primeira linha
            String linha = lerArq.readLine();
            String linhaCifrada = "";
            String textoCifrado = "";
         
            // a variável "linha" recebe o valor "null" quando o processo
            // de repetição atingir o final do arquivo texto
            while (linha != null) {
                linhaCifrada = cifraLinha(toHex(linha.getBytes()), chaveCifragemArquivo, ivSpec,ivCifragemArquivo);
                textoCifrado += linhaCifrada + "\n";
                linha = lerArq.readLine(); // lê da segunda até a última linha
            }
            
            System.out.println(textoCifrado);

            arquivoLer.close();
        } catch (IOException e) {
            System.err.printf("Erro na abertura do arquivo: %s.\n",
                    e.getMessage());
        }

    }

    private static String cifraLinha(String linha, SecretKey chave, IvParameterSpec ivSpec, byte[] iv) throws Exception{
        
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "BCFIPS");
        
        byte chaveByte[] = org.apache.commons.codec.binary.Hex.decodeHex(Hex.encodeHexString(chave.getEncoded()).toCharArray());
        //System.out.println(toHex(chaveByte));
        //System.out.println(Hex.encodeHexString(chave.getEncoded()).toCharArray());
        //System.out.println(chaveByte.length);
        //System.out.println(Hex.encodeHexString(chaveByte));
        
        //SecretKey chaveSecreta = new SecretKeySpec(chaveByte, "AES");
        //byte[] linhaByte = linha.getBytes();
        
        byte linhaByte[] = org.apache.commons.codec.binary.Hex.decodeHex(linha.toCharArray());
        //System.out.println(toHex(linhaByte));
        //System.out.println(new String(linhaByte));
        
        
        //Mudança de chave para testar
        cipher.init(Cipher.ENCRYPT_MODE, chave, ivSpec);
        
        //byte[] linhaCifrada = new byte[cipher.getOutputSize(linhaByte.length)];
        
        String linhaCifradaS = Hex.encodeHexString(cipher.doFinal(linha.getBytes()));
        
        return linhaCifradaS;
        
        /*
        
        //System.out.println(ctLength);
        System.out.println(toHex(linhaByte));
        //ctLength += cipher.doFinal(linhaByte, ctLength);
        cipher.doFinal(linhaCifrada);
        */
        
        /*
        //teste
        System.out.println(linha);
        System.out.println(new String(linhaByte));
        return new String(linhaCifrada);
        */
       
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

    private static void decifraArquivo(String caminhoArquivo) {

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
}
