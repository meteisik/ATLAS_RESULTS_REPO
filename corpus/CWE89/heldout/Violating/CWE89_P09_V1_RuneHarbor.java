import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V1_RuneHarbor {

    static class Container {
        public String containerOne;
    }

    public void runRuneHarbor() throws SQLException {
        String data;
        data = System.getenv("RUNE_HARBOR_FILTER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V1_RuneHarborSink()).queryRuneHarbor(dataContainer);
    }
}

class CWE89_P09_V1_RuneHarborSink {
    public void queryRuneHarbor(CWE89_P09_V1_RuneHarbor.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection runeHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeHarbor");
        Statement runeHarborStatement = null;
        ResultSet runeHarborRows = null;
        try {
            runeHarborStatement = runeHarborConnection.createStatement();
            runeHarborRows = runeHarborStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(runeHarborRows.getRow());
        } finally {
            if (runeHarborRows != null) {
                runeHarborRows.close();
            }
            if (runeHarborStatement != null) {
                runeHarborStatement.close();
            }
            runeHarborConnection.close();
        }
    }
}
