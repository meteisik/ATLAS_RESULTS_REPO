import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P03_V1_CrimsonCometSafe {

    private void sinkCrimsonComet(String data) throws XPathExpressionException {
        String crimsonCometXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            crimsonCometXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            crimsonCometXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] crimsonCometTokens = data.split("||");
            if (crimsonCometTokens.length < 2) {
                return;
            }
            String crimsonCometUser = crimsonCometTokens[0];
            String crimsonCometPass = crimsonCometTokens[1];
            XPath crimsonCometXPath = XPathFactory.newInstance().newXPath();
            InputSource crimsonCometXml = new InputSource(crimsonCometXmlFile);
            String crimsonCometQuery = "//users/user[name/text()='" + crimsonCometUser
                    + "' and pass/text()='" + crimsonCometPass + "']" + "/secret/text()";
            String crimsonCometSecret = (String) crimsonCometXPath.evaluate(crimsonCometQuery, crimsonCometXml, XPathConstants.STRING);
            System.out.println(crimsonCometSecret);
        }
    }

    public void runCrimsonComet() throws XPathExpressionException {
        String data;
        data = "foo";
        sinkCrimsonComet(data);
    }
}
