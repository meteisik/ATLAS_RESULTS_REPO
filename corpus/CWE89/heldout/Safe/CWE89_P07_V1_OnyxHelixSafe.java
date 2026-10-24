import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V1_OnyxHelixSafe {

    public void runOnyxHelix() throws SQLException {
        String data;
        data = (new CWE89_P07_V1_OnyxHelixSafeSource()).loadOnyxHelix();
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

class CWE89_P07_V1_OnyxHelixSafeSource {
    public String loadOnyxHelix() {
        String data;
        data = "foo";
        return data;
    }
}
