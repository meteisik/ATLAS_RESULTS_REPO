import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P01_V1_CrimsonHelix {

    public void runCrimsonHelix() throws XPathExpressionException {
        String data;
        data = System.getenv("CRIMSON_HELIX_ADD");
        String crimsonHelixXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            crimsonHelixXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            crimsonHelixXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] crimsonHelixTokens = data.split("||");
            if (crimsonHelixTokens.length < 2) {
                return;
            }
            String crimsonHelixUser = crimsonHelixTokens[0];
            String crimsonHelixPass = crimsonHelixTokens[1];
            XPath crimsonHelixXPath = XPathFactory.newInstance().newXPath();
            InputSource crimsonHelixXml = new InputSource(crimsonHelixXmlFile);
            String crimsonHelixQuery = "//users/user[name/text()='" + crimsonHelixUser
                    + "' and pass/text()='" + crimsonHelixPass + "']" + "/secret/text()";
            String crimsonHelixSecret = (String) crimsonHelixXPath.evaluate(crimsonHelixQuery, crimsonHelixXml, XPathConstants.STRING);
            System.out.println(crimsonHelixSecret);
        }
    }
}
