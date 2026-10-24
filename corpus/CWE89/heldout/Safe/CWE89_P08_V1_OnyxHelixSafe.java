import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V1_OnyxHelixSafe {

    public void runOnyxHelix() throws SQLException {
        String data;
        data = "foo";
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V1_OnyxHelixSafeSink()).queryOnyxHelix(dataArray);
    }
}

class CWE89_P08_V1_OnyxHelixSafeSink {
    public void queryOnyxHelix(String[] dataArray) throws SQLException {
        String data = dataArray[2];
        Connection onyxHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxHelix");
        Statement onyxHelixStatement = null;
        ResultSet onyxHelixRows = null;
        try {
            onyxHelixStatement = onyxHelixConnection.createStatement();
            onyxHelixRows = onyxHelixStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(onyxHelixRows.getRow());
        } finally {
            if (onyxHelixRows != null) {
                onyxHelixRows.close();
            }
            if (onyxHelixStatement != null) {
                onyxHelixStatement.close();
            }
            onyxHelixConnection.close();
        }
    }
}
