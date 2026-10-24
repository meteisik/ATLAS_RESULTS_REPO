import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V2_RuneHarborSafe {

    public void runRuneHarbor() throws SQLException {
        String data;
        if (true) {
            data = (new CWE89_P07_V2_RuneHarborSafeSource()).loadRuneHarbor();
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

class CWE89_P07_V2_RuneHarborSafeSource {
    public String loadRuneHarbor() {
        String data;
        data = "foo";
        return data;
    }
}
