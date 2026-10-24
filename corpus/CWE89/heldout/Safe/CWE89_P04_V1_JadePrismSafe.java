import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P04_V1_JadePrismSafe {

    private String loadJadePrism() {
        String data;
        data = "foo";
        return data;
    }

    public void runJadePrism() throws SQLException {
        String data = loadJadePrism();
        Connection jadePrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadePrism");
        Statement jadePrismStatement = null;
        ResultSet jadePrismRows = null;
        try {
            jadePrismStatement = jadePrismConnection.createStatement();
            jadePrismRows = jadePrismStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(jadePrismRows.getRow());
        } finally {
            if (jadePrismRows != null) {
                jadePrismRows.close();
            }
            if (jadePrismStatement != null) {
                jadePrismStatement.close();
            }
            jadePrismConnection.close();
        }
    }
}
