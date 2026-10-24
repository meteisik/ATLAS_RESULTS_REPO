import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V2_RuneKestrel {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void runRuneKestrel() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = (new CWE89_P07_V2_RuneKestrelSource()).loadRuneKestrel();
        } else {
            data = null;
        }
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

class CWE89_P07_V2_RuneKestrelSource {
    public String loadRuneKestrel() {
        String data;
        data = System.getenv("RUNE_KESTREL_FILTER");
        return data;
    }
}
