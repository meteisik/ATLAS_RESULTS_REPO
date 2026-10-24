import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V2_RuneHelix {

    public void runRuneHelix() throws SQLException {
        String data;
        if (5 == 5) {
            data = (new CWE89_P07_V2_RuneHelixSource()).loadRuneHelix();
        } else {
            data = null;
        }
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

class CWE89_P07_V2_RuneHelixSource {
    public String loadRuneHelix() {
        String data;
        data = System.getenv("RUNE_HELIX_FILTER");
        return data;
    }
}
