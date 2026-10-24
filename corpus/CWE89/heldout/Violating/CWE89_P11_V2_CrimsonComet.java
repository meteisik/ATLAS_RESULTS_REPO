import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V2_CrimsonComet {
    private static int privateFive = 5;

    public void runCrimsonComet() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("CRIMSON_COMET_FILTER");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V2_CrimsonCometSink()).queryCrimsonComet(dataHashMap);
    }
}

class CWE89_P11_V2_CrimsonCometSink {
    public void queryCrimsonComet(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection crimsonCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonComet");
        Statement crimsonCometStatement = null;
        ResultSet crimsonCometRows = null;
        try {
            crimsonCometStatement = crimsonCometConnection.createStatement();
            crimsonCometRows = crimsonCometStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(crimsonCometRows.getRow());
        } finally {
            if (crimsonCometRows != null) {
                crimsonCometRows.close();
            }
            if (crimsonCometStatement != null) {
                crimsonCometStatement.close();
            }
            crimsonCometConnection.close();
        }
    }
}
