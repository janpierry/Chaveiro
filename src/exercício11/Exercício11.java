/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package exercício11;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import sun.security.krb5.internal.PAData;

/**
 *
 * @author jan
 */
public class Exercício11 {

    private static SecretKey chaveMestre;
    private static String chaveMestreString;
    private static String sal = "a0b7a99de04a63b464752d7787abe186";
    private static int iteracoes;
    
    
    public static void main(String[] args) throws Exception {
        
        Scanner input = new Scanner(System.in);
        System.out.println("---------------Bem vindo ao chaveiro---------------");
        System.out.println("");
        System.out.println("Insira a sua senha: ");
        String senha = input.nextLine();
        
        
        //Número de iterações
        iteracoes = 10000;
        
        chaveMestre = generateDerivedKey(senha, sal, iteracoes);
        chaveMestreString = Hex.encodeHexString(chaveMestre.getEncoded());
        
        System.out.println("A sua chave mestre é: " + chaveMestreString);
        
        menuInicial();
        
        
        
        
    }
    
    public static void menuInicial() throws Exception {
        
        Scanner input = new Scanner(System.in);
        
        System.out.println("");
        System.out.println("------------------Funcionalidades------------------");
        System.out.println("");
        System.out.println("Informe o número da função desejada: ");
        System.out.println("");
        System.out.println("1- Cifrar arquivo");
        System.out.println("");
        String opcao = input.nextLine();
        
        switch(opcao){
            case "1":
                telaCifraArquivo();
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

    }
    
    public static SecretKey generateDerivedKey(String password, String salt, Integer iterations) {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), iterations, 128);
        SecretKeyFactory pbkdf2 = null;
        String derivedPass = null;
        try {
            pbkdf2 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
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
        
        //byte[] chaveByte = Base64.getDecoder().decode(Hex.encodeHexString(chave.getEncoded()));
        byte[] chaveByte = hexStringToByteArray(Hex.encodeHexString(chave.getEncoded()));
        System.out.println(chaveByte.length);
        System.out.println(new String(chaveByte));
        SecretKey chaveSecreta = new SecretKeySpec(chaveByte, "AES");
        //byte[] linhaByte = linha.getBytes();
        
        byte[] linhaByte = hexStringToByteArray(linha);
        //System.out.println(new String(linhaByte));
        
        cipher.init(Cipher.ENCRYPT_MODE, chaveSecreta, ivSpec);
        

        byte[] linhaCifrada = new byte[cipher.getOutputSize(iv.length + linhaByte.length)];
        
        int ctLength = cipher.update(iv, 0, iv.length, linhaCifrada, 0);
        
        ctLength += cipher.update(linhaByte, 0, linhaByte.length, linhaCifrada, ctLength);
        System.out.println(ctLength);
        System.out.println(cipher.getOutputSize(iv.length + linhaByte.length));
        ctLength += cipher.doFinal(linhaCifrada, ctLength);
        
        /*
        int ctLength = cipher.update(linhaByte, 0, linhaByte.length, linhaCifrada, 0);
        System.out.println(linhaCifrada.length);
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
        return null;
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
    
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
}
}
