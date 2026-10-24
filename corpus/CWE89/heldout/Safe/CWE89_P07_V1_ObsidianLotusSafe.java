import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V1_ObsidianLotusSafe {

    public void runObsidianLotus() throws SQLException {
        String data;
        data = (new CWE89_P07_V1_ObsidianLotusSafeSource()).loadObsidianLotus();
        Connection obsidianLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianLotus");
        Statement obsidianLotusStatement = null;
        ResultSet obsidianLotusRows = null;
        try {
            obsidianLotusStatement = obsidianLotusConnection.createStatement();
            obsidianLotusRows = obsidianLotusStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(obsidianLotusRows.getRow());
        } finally {
            if (obsidianLotusRows != null) {
                obsidianLotusRows.close();
            }
            if (obsidianLotusStatement != null) {
                obsidianLotusStatement.close();
            }
            obsidianLotusConnection.close();
        }
    }
}

class CWE89_P07_V1_ObsidianLotusSafeSource {
    public String loadObsidianLotus() {
        String data;
        data = "foo";
        return data;
    }
}
