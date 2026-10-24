import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_RuneRaven {

    public static String data;

    public void runRuneRaven() throws SQLException {
        data = System.getenv("RUNE_RAVEN_FILTER");
        (new CWE89_P10_V1_RuneRavenSink()).queryRuneRaven();
    }
}

class CWE89_P10_V1_RuneRavenSink {
    public void queryRuneRaven() throws SQLException {
        String data = CWE89_P10_V1_RuneRaven.data;
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
}
