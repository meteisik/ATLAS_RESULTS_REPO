import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P03_V1_GoldenSignal {

    private void sinkGoldenSignal(String data) throws XPathExpressionException {
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

    public void runGoldenSignal() throws XPathExpressionException {
        String data;
        data = System.getenv("GOLDEN_SIGNAL_ADD");
        sinkGoldenSignal(data);
    }
}
