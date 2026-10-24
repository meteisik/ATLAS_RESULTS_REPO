import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P02_V1_GoldenCipher {

    public void runGoldenCipher() throws XPathExpressionException {
        String dataCopy;
        {
            String data;
            data = System.getenv("GOLDEN_CIPHER_ADD");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            String goldenCipherXmlFile = null;
            if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
                goldenCipherXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
            } else {
                goldenCipherXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
            }
            if (data != null) {
                String[] goldenCipherTokens = data.split("||");
                if (goldenCipherTokens.length < 2) {
                    return;
                }
                String goldenCipherUser = goldenCipherTokens[0];
                String goldenCipherPass = goldenCipherTokens[1];
                XPath goldenCipherXPath = XPathFactory.newInstance().newXPath();
                InputSource goldenCipherXml = new InputSource(goldenCipherXmlFile);
                String goldenCipherQuery = "//users/user[name/text()='" + goldenCipherUser
                        + "' and pass/text()='" + goldenCipherPass + "']" + "/secret/text()";
                String goldenCipherSecret = (String) goldenCipherXPath.evaluate(goldenCipherQuery, goldenCipherXml, XPathConstants.STRING);
                System.out.println(goldenCipherSecret);
            }
        }
    }
}
