import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V2_CrimsonCometSafe {
    private static int privateFive = 5;

    public void runCrimsonComet() throws XPathExpressionException {
        String data;
        if (privateFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V2_CrimsonCometSafeSink()).sinkCrimsonComet(dataHashMap);
    }
}

class CWE643_P11_V2_CrimsonCometSafeSink {

    public void sinkCrimsonComet(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
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
}
