import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P04_V2_OnyxHelix {

    private String loadOnyxHelix() {
        String data;
        if (true) {
            data = System.getenv("ONYX_HELIX_FILTER");
        } else {
            data = null;
        }
        return data;
    }

    public void runOnyxHelix() throws SQLException {
        String data = loadOnyxHelix();
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
