import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V1_OnyxLantern {

    public void runOnyxLantern() throws SQLException {
        String data;
        data = System.getenv("ONYX_LANTERN_FILTER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V1_OnyxLanternSink()).queryOnyxLantern(dataArray);
    }
}

class CWE89_P08_V1_OnyxLanternSink {
    public void queryOnyxLantern(String[] dataArray) throws SQLException {
        String data = dataArray[2];
        Connection onyxLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxLantern");
        Statement onyxLanternStatement = null;
        ResultSet onyxLanternRows = null;
        try {
            onyxLanternStatement = onyxLanternConnection.createStatement();
            onyxLanternRows = onyxLanternStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(onyxLanternRows.getRow());
        } finally {
            if (onyxLanternRows != null) {
                onyxLanternRows.close();
            }
            if (onyxLanternStatement != null) {
                onyxLanternStatement.close();
            }
            onyxLanternConnection.close();
        }
    }
}
