import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V1_ObsidianLotus {

    public void runObsidianLotus() throws SQLException {
        String data;
        data = System.getenv("OBSIDIAN_LOTUS_FILTER");
        (new CWE89_P06_V1_ObsidianLotusSink()).queryObsidianLotus(data);
    }
}

class CWE89_P06_V1_ObsidianLotusSink {
    public void queryObsidianLotus(String data) throws SQLException {
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
