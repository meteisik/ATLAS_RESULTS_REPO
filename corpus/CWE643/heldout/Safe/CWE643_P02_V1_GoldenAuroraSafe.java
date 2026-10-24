import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P02_V1_GoldenAuroraSafe {

    public void runGoldenAurora() throws XPathExpressionException {
        String dataCopy;
        {
            String data;
            data = "foo";
            dataCopy = data;
        }
        {
            String data = dataCopy;
            String goldenAuroraXmlFile = null;
            if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
                goldenAuroraXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
            } else {
                goldenAuroraXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
            }
            if (data != null) {
                String[] goldenAuroraTokens = data.split("||");
                if (goldenAuroraTokens.length < 2) {
                    return;
                }
                String goldenAuroraUser = goldenAuroraTokens[0];
                String goldenAuroraPass = goldenAuroraTokens[1];
                XPath goldenAuroraXPath = XPathFactory.newInstance().newXPath();
                InputSource goldenAuroraXml = new InputSource(goldenAuroraXmlFile);
                String goldenAuroraQuery = "//users/user[name/text()='" + goldenAuroraUser
                        + "' and pass/text()='" + goldenAuroraPass + "']" + "/secret/text()";
                String goldenAuroraSecret = (String) goldenAuroraXPath.evaluate(goldenAuroraQuery, goldenAuroraXml, XPathConstants.STRING);
                System.out.println(goldenAuroraSecret);
            }
        }
    }
}
