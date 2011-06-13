/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package org.suai.idbased.ibemailet;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
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
import org.suai.idbased.crypto.Client;
import org.suai.idbased.keymng.KeyStorage;
import org.suai.idbased.pkg.PKG;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/**
 *
 * @author foxneig
 */
public class IBEJames extends GenericMailet {
private MailetConfig config;
private String keyStoragePath;
private String password;
private String localhostname;

private KeyStorage ks;
private PKG pkg;
private Client client;
@Override
public void init(MailetConfig config) throws MessagingException {
System.out.println("Init Identity Based Cryptosystem Mailet for JAMES");
super.init(config);
MailetContext context = config.getMailetContext();
keyStoragePath = getInitParameter("keystoragePath");
localhostname = getInitParameter("localhostName");
password = getInitParameter("password");
pkg = new PKG();
        try
          {
            ks = new KeyStorage(keyStoragePath);
          }
        catch (FileNotFoundException ex)
          {
            Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null,
                    ex);
          }

}
private byte [] getAttachments (InputStream is) throws IOException {


            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buff = new byte[8];
            int i = 0;

            i = is.read(buff);
             while (i!=-1) {
                 bos.write(buff,0, i);
                 i = is.read(buff);
             }

        try {
            is.close();
        } catch (IOException ex) {
            Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
        }
            return bos.toByteArray();



    }
    @Override
 public void service(Mail mail) throws MessagingException {
        BigInteger [] keys = new BigInteger[3];
        client = new Client();
        byte [] encrypted = null;
        byte [] body = null;
        byte [] mpk = new byte [1024];
        byte [] msk1 = new byte [512];
        byte [] msk2 = new byte [512];
        BASE64Encoder enc = new BASE64Encoder();
        BASE64Decoder dec = new BASE64Decoder ();
        ByteArrayInputStream bin = null;
        MimeMessage message = mail.getMessage();
        String contentType = message.getContentType();
        
        MailAddress from = mail.getSender();
        Collection recp = mail.getRecipients();
        Iterator<MailAddress> iterator = recp.iterator();
        MailAddress to = iterator.next();
        String text = null;
        String recip = to.toString();
        String sender = from.toString();
        String recip_domain = to.getHost();
        String sender_domain = from.getHost();
        byte[] decrypted = null;
        Multipart mp = null;
        int res = 0;
        // local mail - send not encrypted
        if (recip_domain.equals(this.localhostname) && sender_domain.equals(this.localhostname)) {
            return;
        }
        else
            if (sender_domain.equals(this.localhostname) == false) {
            // sender is not local  - start finding in keystorage and encrypting

            try {
                res = ks.getKey(sender_domain, keys, password);
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchPaddingException ex) {
                Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidKeyException ex) {
                Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IOException ex) {
                Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IllegalBlockSizeException ex) {
                Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
            }
            if (res == 1) {
            pkg.init(keys[0], keys[1], keys[2]);
            if (message.isMimeType("text/plain")) {
            try {
                text = (String) message.getContent();
            } catch (IOException ex) {
                Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
            }
            try {
                body = dec.decodeBuffer(text);
            } catch (IOException ex) {
                Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
            }
            bin = new ByteArrayInputStream(body);
           
                    try {
                        decrypted = client.decryptData(bin, recip, sender, pkg.keyExtract(recip), pkg.getMPK(), pkg.getSigningPublicKey());
                    } catch (FileNotFoundException ex) {
                        Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (IOException ex) {
                        Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (NoSuchAlgorithmException ex) {
                        Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (NoSuchPaddingException ex) {
                        Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (InvalidKeyException ex) {
                        Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (IllegalBlockSizeException ex) {
                        Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (BadPaddingException ex) {
                        Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
                  }
            
            String plaintext = new String(decrypted);
            
            message.setContent(plaintext, contentType);
            message.setHeader(RFC2822Headers.CONTENT_TYPE, contentType);
            message.saveChanges();


        } else if (message.isMimeType("multipart/mixed") || message.isMimeType("multipart/related") || message.isMimeType("multipart/alternative")) {

            try {
                mp = (Multipart) message.getContent();
            } catch (IOException ex) {
                Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
            }

            for (int i = 0, n = mp.getCount(); i < n; i++) {
                Part part = mp.getBodyPart(i);
                if (part.isMimeType("text/plain")) {
                    
                    try {
                        text = (String) part.getContent();
                        } catch (IOException ex) {
                        Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
                    }
                    try {
                        body = dec.decodeBuffer(text);
                    } catch (IOException ex) {
                        Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
                    }
                    bin = new ByteArrayInputStream(body);
                    try {

                        decrypted = client.decryptData(bin, recip, sender, pkg.keyExtract(recip), pkg.getMPK(), pkg.getSigningPublicKey());

                    } catch (FileNotFoundException ex) {
                       Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (IOException ex) {
                        Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (NoSuchAlgorithmException ex) {
                       Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (NoSuchPaddingException ex) {
                       Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (InvalidKeyException ex) {
                       Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (IllegalBlockSizeException ex) {
                       Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (BadPaddingException ex) {
                        Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
                    } 

                    String decr = new String(decrypted);
                    part.setContent(decr, part.getContentType());
                    mp.removeBodyPart((BodyPart) part);
                    mp.addBodyPart((BodyPart) part, i);
                    message.setContent(mp);
                } else {
                    
                    String disposition = part.getDisposition();
                   
                    if ((disposition != null) && ((disposition.equals(Part.ATTACHMENT) || (disposition.equals(Part.INLINE))))) {
                        InputStream inputStream = null;
                        try {
                            
                            text = null;
                            
                            inputStream = part.getInputStream();
                            
                        } catch (IOException ex) {
                           Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
                        }

                        try {
                            
                            body = dec.decodeBuffer(new String (this.getAttachments(inputStream)));
                        } catch (IOException ex) {
                           Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
                        }
                        bin = new ByteArrayInputStream(body);
                        
                        try {
                            
                            decrypted = client.decryptData(bin, recip, sender, pkg.keyExtract(recip), pkg.getMPK(), pkg.getSigningPublicKey());
                        } catch (FileNotFoundException ex) {
                         Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
                        } catch (IOException ex) {
                           Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
                        } catch (NoSuchAlgorithmException ex) {
                           Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
                        } catch (NoSuchPaddingException ex) {
                            Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
                        } catch (InvalidKeyException ex) {
                            Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
                        } catch (IllegalBlockSizeException ex) {
                           Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
                        } catch (BadPaddingException ex) {
                           Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
                        } 
                        
                        part.setContent(decrypted, part.getContentType());
                      
                        mp.removeBodyPart((BodyPart) part);
                       
                        mp.addBodyPart((BodyPart) part, i);
                        
                        message.setContent(mp);
                        
                        message.saveChanges();
                       



                    }
                }
            }


        }
         message.setHeader(RFC2822Headers.CONTENT_TYPE, contentType);
         message.saveChanges();
        
         return;
            }
            else {
                // domain not find in keystorage, do nothing
            }

            }
            else
                if (recip_domain.equals(this.localhostname) == false) {
            try {
                // письмо уходит на другой сервер, зашифруем, если есть ключ, если нет - добавить подпись
                res = ks.getKey(recip_domain, keys, password);
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchPaddingException ex) {
                Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidKeyException ex) {
                Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IOException ex) {
                Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IllegalBlockSizeException ex) {
                Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
            }
                }
        if (res == 1) {
              pkg.init(keys[0], keys[1], keys[2]);
              if (message.isMimeType("text/plain")) {
            try {
                body = this.getAttachments(message.getInputStream());
            } catch (IOException ex) {
                Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
            }
            bin = new ByteArrayInputStream (body);
            
            try {
                encrypted = client.encryptData(bin, client.genPkID(recip, pkg.getMPK()), pkg.getMPK(), pkg.signKeyExtract(sender), pkg.getSigningPublicKey());

            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchPaddingException ex) {
                Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidKeyException ex) {
                Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IOException ex) {
                Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IllegalBlockSizeException ex) {
                Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
            } catch (BadPaddingException ex) {
                Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
            }
               

                String encode = enc.encode(encrypted);
                message.setContent(encode, contentType);
                message.saveChanges();




        }
        else if (message.isMimeType("multipart/mixed") ||message.isMimeType("multipart/related") || message.isMimeType("multipart/alternative")  ) {

            try {
                
                mp = (Multipart) message.getContent();

               

                for (int i = 0, n = mp.getCount(); i < n; i++) {

                    Part part = mp.getBodyPart(i);


                    if (part.isMimeType("text/plain")) {
                    
                    body = this.getAttachments(part.getInputStream());
                    bin = new ByteArrayInputStream (body);
                        try {

                            encrypted = client.encryptData(bin, client.genPkID(recip, pkg.getMPK()), pkg.getMPK(), pkg.signKeyExtract(sender), pkg.getSigningPublicKey());
                        } catch (NoSuchAlgorithmException ex) {
                            Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
                        } catch (NoSuchPaddingException ex) {
                            Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
                        } catch (InvalidKeyException ex) {
                            Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
                        } catch (IllegalBlockSizeException ex) {
                            Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
                        } catch (BadPaddingException ex) {
                            Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
                        }
                     String encode = enc.encode(encrypted);
                  
                     part.setContent(encode, part.getContentType());
                     boolean removeBodyPart = mp.removeBodyPart((BodyPart) part);
                     mp.addBodyPart((BodyPart) part,i);
                     message.setContent(mp);

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
                    
                    if ((disposition != null) && ((disposition.equals(Part.ATTACHMENT) || (disposition.equals(Part.INLINE))))) {

                        
                            try {
                                try {
                                    encrypted = client.encryptData(bin, client.genPkID(recip, pkg.getMPK()), pkg.getMPK(), pkg.signKeyExtract(sender), pkg.getSigningPublicKey());
                                } catch (NoSuchPaddingException ex) {
                                    Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
                                } catch (InvalidKeyException ex) {
                                    Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
                                } catch (IllegalBlockSizeException ex) {
                                    Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
                                } catch (BadPaddingException ex) {
                                    Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
                                }
                            } catch (NoSuchAlgorithmException ex) {
                                Logger.getLogger(IBEJames.class.getName()).log(Level.SEVERE, null, ex);
                            }
                        String encode = enc.encode(encrypted);

                        part.setContent(encode, part.getContentType());
                       
                        boolean removeBodyPart = mp.removeBodyPart((BodyPart) part);
                        mp.addBodyPart((BodyPart) part,i);
                        message.setContent(mp);
                        message.saveChanges();





                    



                    }
                    }
                }
            } catch (IOException ex) {
               log("Cannot to get attaches");
            }
        }

        message.setHeader(RFC2822Headers.CONTENT_TYPE, contentType);

        



        }
        else {
            //ключ не найден, отправлять в открытом виде
            return;
        }







    }




}
