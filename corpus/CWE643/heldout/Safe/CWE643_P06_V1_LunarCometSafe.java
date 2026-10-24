import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P06_V1_LunarCometSafe {

    public void runLunarComet() throws XPathExpressionException {
        String data;
        data = "foo";
        (new CWE643_P06_V1_LunarCometSafeSink()).sinkLunarComet(data);
    }
}

class CWE643_P06_V1_LunarCometSafeSink {

    public void sinkLunarComet(String data) throws XPathExpressionException {
        String lunarCometXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            lunarCometXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            lunarCometXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] lunarCometTokens = data.split("||");
            if (lunarCometTokens.length < 2) {
                return;
            }
            String lunarCometUser = lunarCometTokens[0];
            String lunarCometPass = lunarCometTokens[1];
            XPath lunarCometXPath = XPathFactory.newInstance().newXPath();
            InputSource lunarCometXml = new InputSource(lunarCometXmlFile);
            String lunarCometQuery = "//users/user[name/text()='" + lunarCometUser
                    + "' and pass/text()='" + lunarCometPass + "']" + "/secret/text()";
            String lunarCometSecret = (String) lunarCometXPath.evaluate(lunarCometQuery, lunarCometXml, XPathConstants.STRING);
            System.out.println(lunarCometSecret);
        }
    }
}
