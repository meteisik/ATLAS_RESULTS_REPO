import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P02_V1_ArcticRavenSafe {

    public void runArcticRaven() throws XPathExpressionException {
        String dataCopy;
        {
            String data;
            data = "foo";
            dataCopy = data;
        }
        {
            String data = dataCopy;
            String arcticRavenXmlFile = null;
            if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
                arcticRavenXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
            } else {
                arcticRavenXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
            }
            if (data != null) {
                String[] arcticRavenTokens = data.split("||");
                if (arcticRavenTokens.length < 2) {
                    return;
                }
                String arcticRavenUser = arcticRavenTokens[0];
                String arcticRavenPass = arcticRavenTokens[1];
                XPath arcticRavenXPath = XPathFactory.newInstance().newXPath();
                InputSource arcticRavenXml = new InputSource(arcticRavenXmlFile);
                String arcticRavenQuery = "//users/user[name/text()='" + arcticRavenUser
                        + "' and pass/text()='" + arcticRavenPass + "']" + "/secret/text()";
                String arcticRavenSecret = (String) arcticRavenXPath.evaluate(arcticRavenQuery, arcticRavenXml, XPathConstants.STRING);
                System.out.println(arcticRavenSecret);
            }
        }
    }
}
