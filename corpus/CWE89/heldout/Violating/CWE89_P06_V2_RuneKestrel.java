import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V2_RuneKestrel {

    public void runRuneKestrel() throws SQLException {
        String data;
        if (true) {
            data = System.getenv("RUNE_KESTREL_FILTER");
        } else {
            data = null;
        }
        (new CWE89_P06_V2_RuneKestrelSink()).queryRuneKestrel(data);
    }
}

class CWE89_P06_V2_RuneKestrelSink {
    public void queryRuneKestrel(String data) throws SQLException {
        Connection runeKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeKestrel");
        Statement runeKestrelStatement = null;
        ResultSet runeKestrelRows = null;
        try {
            runeKestrelStatement = runeKestrelConnection.createStatement();
            runeKestrelRows = runeKestrelStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(runeKestrelRows.getRow());
        } finally {
            if (runeKestrelRows != null) {
                runeKestrelRows.close();
            }
            if (runeKestrelStatement != null) {
                runeKestrelStatement.close();
            }
            runeKestrelConnection.close();
        }
    }
}
