import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V1_VelvetSignalSafe {

    public void runVelvetSignal() throws SQLException {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V1_VelvetSignalSafeSink()).queryVelvetSignal(dataHashMap);
    }
}

class CWE89_P11_V1_VelvetSignalSafeSink {
    public void queryVelvetSignal(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection velvetSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetSignal");
        Statement velvetSignalStatement = null;
        ResultSet velvetSignalRows = null;
        try {
            velvetSignalStatement = velvetSignalConnection.createStatement();
            velvetSignalRows = velvetSignalStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(velvetSignalRows.getRow());
        } finally {
            if (velvetSignalRows != null) {
                velvetSignalRows.close();
            }
            if (velvetSignalStatement != null) {
                velvetSignalStatement.close();
            }
            velvetSignalConnection.close();
        }
    }
}
