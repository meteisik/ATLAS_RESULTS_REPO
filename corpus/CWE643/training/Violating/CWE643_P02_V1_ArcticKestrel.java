import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P02_V1_ArcticKestrel {

    public void runArcticKestrel() throws XPathExpressionException {
        String dataCopy;
        {
            String data;
            data = System.getenv("ARCTIC_KESTREL_ADD");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            String arcticKestrelXmlFile = null;
            if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
                arcticKestrelXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
            } else {
                arcticKestrelXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
            }
            if (data != null) {
                String[] arcticKestrelTokens = data.split("||");
                if (arcticKestrelTokens.length < 2) {
                    return;
                }
                String arcticKestrelUser = arcticKestrelTokens[0];
                String arcticKestrelPass = arcticKestrelTokens[1];
                XPath arcticKestrelXPath = XPathFactory.newInstance().newXPath();
                InputSource arcticKestrelXml = new InputSource(arcticKestrelXmlFile);
                String arcticKestrelQuery = "//users/user[name/text()='" + arcticKestrelUser
                        + "' and pass/text()='" + arcticKestrelPass + "']" + "/secret/text()";
                String arcticKestrelSecret = (String) arcticKestrelXPath.evaluate(arcticKestrelQuery, arcticKestrelXml, XPathConstants.STRING);
                System.out.println(arcticKestrelSecret);
            }
        }
    }
}
