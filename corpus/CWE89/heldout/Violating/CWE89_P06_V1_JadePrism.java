import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V1_JadePrism {

    public void runJadePrism() throws SQLException {
        String data;
        data = System.getenv("JADE_PRISM_FILTER");
        (new CWE89_P06_V1_JadePrismSink()).queryJadePrism(data);
    }
}

class CWE89_P06_V1_JadePrismSink {
    public void queryJadePrism(String data) throws SQLException {
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
