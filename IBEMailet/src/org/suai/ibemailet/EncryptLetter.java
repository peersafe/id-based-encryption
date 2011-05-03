/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package org.suai.ibemailet;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.mail.BodyPart;
import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.Part;
import javax.mail.internet.MimeMessage;
import org.apache.mailet.GenericMailet;
import org.apache.mailet.Mail;
import org.apache.mailet.MailAddress;
import org.apache.mailet.MailetConfig;
import org.apache.mailet.MailetContext;
import org.apache.mailet.RFC2822Headers;
import org.suai.idbased.Client;
import org.suai.idbased.PKG;
import org.suai.idbased.Util;
import org.apache.james.security.InitJCE;
import org.suai.idbased.Cryptocontainer;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/**
 *
 * @author foxneig
 */
public class EncryptLetter extends GenericMailet {
    private MailetConfig config;
    private String mpk_path;
    private String msk1_path;
    private String msk2_path;
    private PKG pkg;
    private Client client;


    @Override
    public void destroy () {
        System.out.println ("Destroy");

        }

    @Override
    public String getMailetInfo() {
        return "IdBasedEncrypt Mailet";
    }

    @Override
    public MailetConfig getMailetConfig() {
        return config;
    }

    @Override
    public void init(MailetConfig config) throws MessagingException {
        
            System.out.println("Init IdBasedEncryptMailet");
    
              
           

            

            
            
            super.init(config);
            MailetContext context = config.getMailetContext();
            mpk_path = getInitParameter("mpkPath");
            msk1_path = getInitParameter("msk1Path");
            msk2_path = getInitParameter("msk2Path");
            pkg = new PKG();
        try {
            pkg.MPK = Util.readKeyData(new FileInputStream(mpk_path));
        } catch (IOException ex) {
            Logger.getLogger(EncryptLetter.class.getName()).log(Level.SEVERE, null, ex);
        }
        try {
            pkg.P = Util.readKeyData(new FileInputStream(msk1_path));
        } catch (IOException ex) {
            Logger.getLogger(EncryptLetter.class.getName()).log(Level.SEVERE, null, ex);
        }
        try {
            pkg.Q = Util.readKeyData(new FileInputStream(msk2_path));
        } catch (IOException ex) {
            Logger.getLogger(EncryptLetter.class.getName()).log(Level.SEVERE, null, ex);
        }
            pkg.getSecretExponent();
       




    }
     public byte [] getAttachments (InputStream is) {


            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buff = new byte[8];
            int i = 0;
            do {
                try {
                    i = is.read(buff);
                    bos.write(buff);
                } catch (IOException ex) {
                    log ("Cannot read from attaches");
                }

            } while (i != -1);
       
            //bos.close();
       
        try {
            is.close();
        } catch (IOException ex) {
            Logger.getLogger(EncryptLetter.class.getName()).log(Level.SEVERE, null, ex);
        }
            return bos.toByteArray();



    }

    @Override
    public void service(Mail mail) throws MessagingException {
        client = new Client();
        byte [] encrypted = null;
        byte [] body = null;
        BASE64Encoder enc = new BASE64Encoder();
        BASE64Decoder dec = new BASE64Decoder ();

        ByteArrayInputStream bin = null;
        MimeMessage message = mail.getMessage();
        String contentType = message.getContentType();
        System.out.println (contentType);
        MailAddress from = mail.getSender();
        Collection to = mail.getRecipients();
        Iterator<MailAddress> iterator = to.iterator();
        String recip = iterator.next().toString();
        String sender = from.toString();
        System.out.println ("E-mail FROM: " + sender);
        System.out.println ("E-mail TO: "+recip);
        if (message.isMimeType("text/plain")) {
            try {
                body = this.getAttachments(message.getInputStream());
            } catch (IOException ex) {
                Logger.getLogger(EncryptLetter.class.getName()).log(Level.SEVERE, null, ex);
            }
            bin = new ByteArrayInputStream (body);           
            System.out.println ("Encrypt mail body...");
            try {
                encrypted = client.encryptData(bin, client.genPkID(recip, pkg.MPK), pkg.MPK, pkg.signKeyExtract(sender), pkg.e);
                
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(EncryptLetter.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchPaddingException ex) {
                Logger.getLogger(EncryptLetter.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidKeyException ex) {
                Logger.getLogger(EncryptLetter.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IOException ex) {
                Logger.getLogger(EncryptLetter.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IllegalBlockSizeException ex) {
                Logger.getLogger(EncryptLetter.class.getName()).log(Level.SEVERE, null, ex);
            } catch (BadPaddingException ex) {
                Logger.getLogger(EncryptLetter.class.getName()).log(Level.SEVERE, null, ex);
            }
                System.out.println ("Done");
               
                String encode = enc.encode(encrypted);
                message.setContent(encode, contentType);
                message.saveChanges();
                
         


        }
        else if (message.isMimeType("multipart/mixed") ||message.isMimeType("multipart/related") || message.isMimeType("multipart/alternative")  ) {

            try {
                // здесь надо сохранить аттачи
                Multipart mp = (Multipart) message.getContent();

                System.out.println ("PartsNum: "+mp.getCount());

                for (int i = 0, n = mp.getCount(); i < n; i++) {

                    Part part = mp.getBodyPart(i);
                   

                    if (part.isMimeType("text/plain")) {
                     System.out.println ("Try to encrypt text");
                    body = this.getAttachments(part.getInputStream());
                    bin = new ByteArrayInputStream (body);
                        try {

                            encrypted = client.encryptData(bin, client.genPkID(recip, pkg.MPK), pkg.MPK, pkg.signKeyExtract(sender), pkg.e);
                        } catch (NoSuchAlgorithmException ex) {
                            Logger.getLogger(EncryptLetter.class.getName()).log(Level.SEVERE, null, ex);
                        } catch (NoSuchPaddingException ex) {
                            Logger.getLogger(EncryptLetter.class.getName()).log(Level.SEVERE, null, ex);
                        } catch (InvalidKeyException ex) {
                            Logger.getLogger(EncryptLetter.class.getName()).log(Level.SEVERE, null, ex);
                        } catch (IllegalBlockSizeException ex) {
                            Logger.getLogger(EncryptLetter.class.getName()).log(Level.SEVERE, null, ex);
                        } catch (BadPaddingException ex) {
                            Logger.getLogger(EncryptLetter.class.getName()).log(Level.SEVERE, null, ex);
                        }
                     String encode = enc.encode(encrypted);
                   //  message.setContent(encode, contentType);
                     part.setContent(encode, part.getContentType());
                     boolean removeBodyPart = mp.removeBodyPart((BodyPart) part);
                     mp.addBodyPart((BodyPart) part,i);
                     message.setContent(mp);
                     message.saveChanges();
                     encrypted = null;
                     body = null;
                     bin = null;
//
;

                    }
                    else {
                    body = this.getAttachments(part.getInputStream());
                    bin = new ByteArrayInputStream (body);

                    String disposition = part.getDisposition();
                    System.out.println ("Disposition "+disposition);
                    if ((disposition != null) && ((disposition.equals(Part.ATTACHMENT) || (disposition.equals(Part.INLINE))))) {

                        System.out.println ("Try to encrypt attache");
                            try {
                                try {
                                    encrypted = client.encryptData(bin, client.genPkID(recip, pkg.MPK), pkg.MPK, pkg.signKeyExtract(sender), pkg.e);
                                } catch (NoSuchPaddingException ex) {
                                    Logger.getLogger(EncryptLetter.class.getName()).log(Level.SEVERE, null, ex);
                                } catch (InvalidKeyException ex) {
                                    Logger.getLogger(EncryptLetter.class.getName()).log(Level.SEVERE, null, ex);
                                } catch (IllegalBlockSizeException ex) {
                                    Logger.getLogger(EncryptLetter.class.getName()).log(Level.SEVERE, null, ex);
                                } catch (BadPaddingException ex) {
                                    Logger.getLogger(EncryptLetter.class.getName()).log(Level.SEVERE, null, ex);
                                }
                            } catch (NoSuchAlgorithmException ex) {
                                Logger.getLogger(EncryptLetter.class.getName()).log(Level.SEVERE, null, ex);
                            }
                        String encode = enc.encode(encrypted);

                        part.setContent(encode, part.getContentType());
                        //part.setFileName("EncryptedFile");
                        boolean removeBodyPart = mp.removeBodyPart((BodyPart) part);
                        mp.addBodyPart((BodyPart) part,i);
                        message.setContent(mp);
                        message.saveChanges();


                        




                     System.out.println ("Attache is encrypted");



                    }
                    }
                }
            } catch (IOException ex) {
               log("Cannot to get attaches");
            }
        }
        message.setHeader(RFC2822Headers.CONTENT_TYPE, contentType);
        
        System.out.println ("Ended");






    }


}
