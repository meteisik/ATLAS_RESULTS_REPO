import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P02_V2_JadeMantis {
    private static boolean privateTrue = true;

    public void runJadeMantis() throws XPathExpressionException {
        String dataCopy;
        {
            String data;
            if (privateTrue) {
                data = System.getenv("JADE_MANTIS_ADD");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            String jadeMantisXmlFile = null;
            if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
                jadeMantisXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
            } else {
                jadeMantisXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
            }
            if (data != null) {
                String[] jadeMantisTokens = data.split("||");
                if (jadeMantisTokens.length < 2) {
                    return;
                }
                String jadeMantisUser = jadeMantisTokens[0];
                String jadeMantisPass = jadeMantisTokens[1];
                XPath jadeMantisXPath = XPathFactory.newInstance().newXPath();
                InputSource jadeMantisXml = new InputSource(jadeMantisXmlFile);
                String jadeMantisQuery = "//users/user[name/text()='" + jadeMantisUser
                        + "' and pass/text()='" + jadeMantisPass + "']" + "/secret/text()";
                String jadeMantisSecret = (String) jadeMantisXPath.evaluate(jadeMantisQuery, jadeMantisXml, XPathConstants.STRING);
                System.out.println(jadeMantisSecret);
            }
        }
    }
}
