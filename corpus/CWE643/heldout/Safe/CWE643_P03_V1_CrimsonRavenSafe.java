import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P03_V1_CrimsonRavenSafe {

    private void sinkCrimsonRaven(String data) throws XPathExpressionException {
        String crimsonRavenXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            crimsonRavenXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            crimsonRavenXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] crimsonRavenTokens = data.split("||");
            if (crimsonRavenTokens.length < 2) {
                return;
            }
            String crimsonRavenUser = crimsonRavenTokens[0];
            String crimsonRavenPass = crimsonRavenTokens[1];
            XPath crimsonRavenXPath = XPathFactory.newInstance().newXPath();
            InputSource crimsonRavenXml = new InputSource(crimsonRavenXmlFile);
            String crimsonRavenQuery = "//users/user[name/text()='" + crimsonRavenUser
                    + "' and pass/text()='" + crimsonRavenPass + "']" + "/secret/text()";
            String crimsonRavenSecret = (String) crimsonRavenXPath.evaluate(crimsonRavenQuery, crimsonRavenXml, XPathConstants.STRING);
            System.out.println(crimsonRavenSecret);
        }
    }

    public void runCrimsonRaven() throws XPathExpressionException {
        String data;
        data = "foo";
        sinkCrimsonRaven(data);
    }
}
