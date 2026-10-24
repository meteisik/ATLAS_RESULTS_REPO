import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P04_V2_ObsidianKestrel {
    private static boolean privateReturnsTrue() { return true; }

    private String loadObsidianKestrel() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("OBSIDIAN_KESTREL_FILTER");
        } else {
            data = null;
        }
        return data;
    }

    public void runObsidianKestrel() throws SQLException {
        String data = loadObsidianKestrel();
        Connection obsidianKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianKestrel");
        Statement obsidianKestrelStatement = null;
        ResultSet obsidianKestrelRows = null;
        try {
            obsidianKestrelStatement = obsidianKestrelConnection.createStatement();
            obsidianKestrelRows = obsidianKestrelStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(obsidianKestrelRows.getRow());
        } finally {
            if (obsidianKestrelRows != null) {
                obsidianKestrelRows.close();
            }
            if (obsidianKestrelStatement != null) {
                obsidianKestrelStatement.close();
            }
            obsidianKestrelConnection.close();
        }
    }
}
