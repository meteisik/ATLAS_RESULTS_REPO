import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V1_RuneHelix {

    static class Container {
        public String containerOne;
    }

    public void runRuneHelix() throws SQLException {
        String data;
        data = System.getenv("RUNE_HELIX_FILTER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V1_RuneHelixSink()).queryRuneHelix(dataContainer);
    }
}

class CWE89_P09_V1_RuneHelixSink {
    public void queryRuneHelix(CWE89_P09_V1_RuneHelix.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection runeHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeHelix");
        Statement runeHelixStatement = null;
        ResultSet runeHelixRows = null;
        try {
            runeHelixStatement = runeHelixConnection.createStatement();
            runeHelixRows = runeHelixStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(runeHelixRows.getRow());
        } finally {
            if (runeHelixRows != null) {
                runeHelixRows.close();
            }
            if (runeHelixStatement != null) {
                runeHelixStatement.close();
            }
            runeHelixConnection.close();
        }
    }
}
