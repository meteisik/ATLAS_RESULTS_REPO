import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V2_RuneHarbor {

    public void runRuneHarbor() throws SQLException {
        String data;
        while (true) {
            data = System.getenv("RUNE_HARBOR_FILTER");
            break;
        }
        (new CWE89_P06_V2_RuneHarborSink()).queryRuneHarbor(data);
    }
}

class CWE89_P06_V2_RuneHarborSink {
    public void queryRuneHarbor(String data) throws SQLException {
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
