import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V2_RuneHarbor {

    public void runRuneHarbor() throws SQLException {
        String data;
        if (true) {
            data = (new CWE89_P07_V2_RuneHarborSource()).loadRuneHarbor();
        } else {
            data = null;
        }
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

class CWE89_P07_V2_RuneHarborSource {
    public String loadRuneHarbor() {
        String data;
        data = System.getenv("RUNE_HARBOR_FILTER");
        return data;
    }
}
