import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P03_V1_CrimsonHarborSafe {

    private void sinkCrimsonHarbor(String data) throws XPathExpressionException {
        String crimsonHarborXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            crimsonHarborXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            crimsonHarborXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] crimsonHarborTokens = data.split("||");
            if (crimsonHarborTokens.length < 2) {
                return;
            }
            String crimsonHarborUser = crimsonHarborTokens[0];
            String crimsonHarborPass = crimsonHarborTokens[1];
            XPath crimsonHarborXPath = XPathFactory.newInstance().newXPath();
            InputSource crimsonHarborXml = new InputSource(crimsonHarborXmlFile);
            String crimsonHarborQuery = "//users/user[name/text()='" + crimsonHarborUser
                    + "' and pass/text()='" + crimsonHarborPass + "']" + "/secret/text()";
            String crimsonHarborSecret = (String) crimsonHarborXPath.evaluate(crimsonHarborQuery, crimsonHarborXml, XPathConstants.STRING);
            System.out.println(crimsonHarborSecret);
        }
    }

    public void runCrimsonHarbor() throws XPathExpressionException {
        String data;
        data = "foo";
        sinkCrimsonHarbor(data);
    }
}
