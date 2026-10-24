import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P02_V2_GoldenSignal {

    public void runGoldenSignal() throws XPathExpressionException {
        String dataCopy;
        {
            String data;
            if (5 == 5) {
                data = System.getenv("GOLDEN_SIGNAL_ADD");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            String goldenSignalXmlFile = null;
            if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
                goldenSignalXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
            } else {
                goldenSignalXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
            }
            if (data != null) {
                String[] goldenSignalTokens = data.split("||");
                if (goldenSignalTokens.length < 2) {
                    return;
                }
                String goldenSignalUser = goldenSignalTokens[0];
                String goldenSignalPass = goldenSignalTokens[1];
                XPath goldenSignalXPath = XPathFactory.newInstance().newXPath();
                InputSource goldenSignalXml = new InputSource(goldenSignalXmlFile);
                String goldenSignalQuery = "//users/user[name/text()='" + goldenSignalUser
                        + "' and pass/text()='" + goldenSignalPass + "']" + "/secret/text()";
                String goldenSignalSecret = (String) goldenSignalXPath.evaluate(goldenSignalQuery, goldenSignalXml, XPathConstants.STRING);
                System.out.println(goldenSignalSecret);
            }
        }
    }
}
