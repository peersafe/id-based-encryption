/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.suai.ibemailet;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
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
import org.suai.idbased.DecryptException;
import org.suai.idbased.PKG;
import org.suai.idbased.Util;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/**
 *
 * @author foxneig
 */
public class DecryptLetter extends GenericMailet {

    private MailetConfig config;
    private String mpk_path;
    private String msk1_path;
    private String msk2_path;
    private PKG pkg;
    private Client client;

    @Override
    public void destroy() {
        System.out.println("Destroy");

    }

    @Override
    public String getMailetInfo() {
        return "IdBasedDecrypt Mailet";
    }

    @Override
    public MailetConfig getMailetConfig() {
        return config;
    }

    @Override
    public void init(MailetConfig config) throws MessagingException {

        System.out.println("Init IdBasedDecryptMailet");
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

    public byte[] getAttachments(InputStream is) {


        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buff = new byte[8];
        int i = 0;
        do {
            try {
                i = is.read(buff);
                bos.write(buff);
            } catch (IOException ex) {
                log("Cannot read from attaches");
            }

        } while (i != -1);
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
        byte[] decrypted = null;
        InputStream is = null;
        Multipart mp = null;
        byte[] body = null;
        ByteArrayInputStream bin = null;
        String text = null;
        BASE64Encoder enc = new BASE64Encoder();
        BASE64Decoder dec = new BASE64Decoder();
        MimeMessage message = mail.getMessage();
        String contentType = message.getContentType();
        System.out.println(contentType);
        MailAddress from = mail.getSender();
        Collection to = mail.getRecipients();
        Iterator<MailAddress> iterator = to.iterator();
        String recip = iterator.next().toString();
        String sender = from.toString();
        System.out.println("E-mail FROM: " + sender);
        System.out.println("E-mail TO: " + recip);
        if (message.isMimeType("text/plain")) {
            try {
                text = (String) message.getContent();
            } catch (IOException ex) {
                Logger.getLogger(DecryptLetter.class.getName()).log(Level.SEVERE, null, ex);
            }
            try {
                body = dec.decodeBuffer(text);
            } catch (IOException ex) {
                Logger.getLogger(DecryptLetter.class.getName()).log(Level.SEVERE, null, ex);
            }
            bin = new ByteArrayInputStream(body);
            System.out.println("Decrypt mail body...");
            try {
                try {
                    decrypted = client.decryptData(bin, recip, sender, pkg.keyExtract(recip), pkg.MPK, pkg.e);
                } catch (FileNotFoundException ex) {
                    Logger.getLogger(DecryptLetter.class.getName()).log(Level.SEVERE, null, ex);
                } catch (DecryptException ex) {
                    Logger.getLogger(DecryptLetter.class.getName()).log(Level.SEVERE, null, ex);
                }
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
            System.out.println("Done");
            String plaintext = new String(decrypted);
            message.setContent(plaintext, contentType);
            message.setHeader(RFC2822Headers.CONTENT_TYPE, contentType);
            message.saveChanges();


        } else if (message.isMimeType("multipart/mixed") || message.isMimeType("multipart/related") || message.isMimeType("multipart/alternative")) {

            try {
                mp = (Multipart) message.getContent();
            } catch (IOException ex) {
                Logger.getLogger(DecryptLetter.class.getName()).log(Level.SEVERE, null, ex);
            }

            for (int i = 0, n = mp.getCount(); i < n; i++) {
                Part part = mp.getBodyPart(i);
                if (part.isMimeType("text/plain")) {
                    System.out.println("Try to decrypt text");
                    try {
                        text = (String) part.getContent();
                    } catch (IOException ex) {
                        Logger.getLogger(DecryptLetter.class.getName()).log(Level.SEVERE, null, ex);
                    }
                    try {
                        body = dec.decodeBuffer(text);
                    } catch (IOException ex) {
                        Logger.getLogger(DecryptLetter.class.getName()).log(Level.SEVERE, null, ex);
                    }
                    bin = new ByteArrayInputStream(body);
                    try {
                        decrypted = client.decryptData(bin, recip, sender, pkg.keyExtract(recip), pkg.MPK, pkg.e);
                    } catch (FileNotFoundException ex) {
                        Logger.getLogger(DecryptLetter.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (IOException ex) {
                        Logger.getLogger(DecryptLetter.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (NoSuchAlgorithmException ex) {
                        Logger.getLogger(DecryptLetter.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (NoSuchPaddingException ex) {
                        Logger.getLogger(DecryptLetter.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (InvalidKeyException ex) {
                        Logger.getLogger(DecryptLetter.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (IllegalBlockSizeException ex) {
                        Logger.getLogger(DecryptLetter.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (BadPaddingException ex) {
                        Logger.getLogger(DecryptLetter.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (DecryptException ex) {
                        Logger.getLogger(DecryptLetter.class.getName()).log(Level.SEVERE, null, ex);
                    }
                    part.setContent(new String(decrypted), part.getContentType());
                    mp.removeBodyPart((BodyPart) part);
                    mp.addBodyPart((BodyPart) part, i);
                    message.setContent(mp);
                    message.saveChanges();

                } else {

                    String disposition = part.getDisposition();
                    if ((disposition != null) && ((disposition.equals(Part.ATTACHMENT) || (disposition.equals(Part.INLINE))))) {
                        try {
                            text = (String) part.getContent();
                        } catch (IOException ex) {
                            Logger.getLogger(DecryptLetter.class.getName()).log(Level.SEVERE, null, ex);
                        }
                        try {
                            body = dec.decodeBuffer(text);
                        } catch (IOException ex) {
                            Logger.getLogger(DecryptLetter.class.getName()).log(Level.SEVERE, null, ex);
                        }
                        bin = new ByteArrayInputStream(body);
                        System.out.println("Try to decrypt attache");
                        try {
                            decrypted = client.decryptData(bin, recip, sender, pkg.keyExtract(recip), pkg.MPK, pkg.e);
                        } catch (FileNotFoundException ex) {
                            Logger.getLogger(DecryptLetter.class.getName()).log(Level.SEVERE, null, ex);
                        } catch (IOException ex) {
                            Logger.getLogger(DecryptLetter.class.getName()).log(Level.SEVERE, null, ex);
                        } catch (NoSuchAlgorithmException ex) {
                            Logger.getLogger(DecryptLetter.class.getName()).log(Level.SEVERE, null, ex);
                        } catch (NoSuchPaddingException ex) {
                            Logger.getLogger(DecryptLetter.class.getName()).log(Level.SEVERE, null, ex);
                        } catch (InvalidKeyException ex) {
                            Logger.getLogger(DecryptLetter.class.getName()).log(Level.SEVERE, null, ex);
                        } catch (IllegalBlockSizeException ex) {
                            Logger.getLogger(DecryptLetter.class.getName()).log(Level.SEVERE, null, ex);
                        } catch (BadPaddingException ex) {
                            Logger.getLogger(DecryptLetter.class.getName()).log(Level.SEVERE, null, ex);
                        } catch (DecryptException ex) {
                            Logger.getLogger(DecryptLetter.class.getName()).log(Level.SEVERE, null, ex);
                        }

                        part.setContent(decrypted, part.getContentType());
                        mp.removeBodyPart((BodyPart) part);
                        mp.addBodyPart((BodyPart) part, i);
                        message.setContent(mp);
                        message.saveChanges();
                        System.out.println("Attache is decrypted");



                    }
                }
            }

        }
        message.setHeader(RFC2822Headers.CONTENT_TYPE, contentType);

        System.out.println("Ended");






    }
}
