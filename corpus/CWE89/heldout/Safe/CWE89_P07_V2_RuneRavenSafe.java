import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V2_RuneRavenSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void runRuneRaven() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = (new CWE89_P07_V2_RuneRavenSafeSource()).loadRuneRaven();
        } else {
            data = null;
        }
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

class CWE89_P07_V2_RuneRavenSafeSource {
    public String loadRuneRaven() {
        String data;
        data = "foo";
        return data;
    }
}
