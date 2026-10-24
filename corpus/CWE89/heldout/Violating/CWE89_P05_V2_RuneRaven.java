import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P05_V2_RuneRaven {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    private String runeRavenData;

    private void queryRuneRaven() throws SQLException {
        String data = runeRavenData;
        Connection runeRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeRaven");
        Statement runeRavenStatement = null;
        ResultSet runeRavenRows = null;
        try {
            runeRavenStatement = runeRavenConnection.createStatement();
            runeRavenRows = runeRavenStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(runeRavenRows.getRow());
        } finally {
            if (runeRavenRows != null) {
                runeRavenRows.close();
            }
            if (runeRavenStatement != null) {
                runeRavenStatement.close();
            }
            runeRavenConnection.close();
        }
    }

    public void runRuneRaven() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("RUNE_RAVEN_FILTER");
        } else {
            data = null;
        }
        runeRavenData = data;
        queryRuneRaven();
    }
}
