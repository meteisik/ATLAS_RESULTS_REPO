import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V2_SaffronPrism {

    public void runSaffronPrism() throws SQLException {
        String data;
        while (true) {
            data = (new CWE89_P07_V2_SaffronPrismSource()).loadSaffronPrism();
            break;
        }
        Connection saffronPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronPrism");
        Statement saffronPrismStatement = null;
        ResultSet saffronPrismRows = null;
        try {
            saffronPrismStatement = saffronPrismConnection.createStatement();
            saffronPrismRows = saffronPrismStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(saffronPrismRows.getRow());
        } finally {
            if (saffronPrismRows != null) {
                saffronPrismRows.close();
            }
            if (saffronPrismStatement != null) {
                saffronPrismStatement.close();
            }
            saffronPrismConnection.close();
        }
    }
}

class CWE89_P07_V2_SaffronPrismSource {
    public String loadSaffronPrism() {
        String data;
        data = System.getenv("SAFFRON_PRISM_FILTER");
        return data;
    }
}
