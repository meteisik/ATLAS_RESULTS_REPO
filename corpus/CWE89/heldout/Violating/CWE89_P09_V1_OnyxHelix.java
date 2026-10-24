import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V1_OnyxHelix {

    static class Container {
        public String containerOne;
    }

    public void runOnyxHelix() throws SQLException {
        String data;
        data = System.getenv("ONYX_HELIX_FILTER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V1_OnyxHelixSink()).queryOnyxHelix(dataContainer);
    }
}

class CWE89_P09_V1_OnyxHelixSink {
    public void queryOnyxHelix(CWE89_P09_V1_OnyxHelix.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
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
