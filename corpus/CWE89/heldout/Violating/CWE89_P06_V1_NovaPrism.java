import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V1_NovaPrism {

    public void runNovaPrism() throws SQLException {
        String data;
        data = System.getenv("NOVA_PRISM_FILTER");
        (new CWE89_P06_V1_NovaPrismSink()).queryNovaPrism(data);
    }
}

class CWE89_P06_V1_NovaPrismSink {
    public void queryNovaPrism(String data) throws SQLException {
        Connection novaPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaPrism");
        Statement novaPrismStatement = null;
        ResultSet novaPrismRows = null;
        try {
            novaPrismStatement = novaPrismConnection.createStatement();
            novaPrismRows = novaPrismStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(novaPrismRows.getRow());
        } finally {
            if (novaPrismRows != null) {
                novaPrismRows.close();
            }
            if (novaPrismStatement != null) {
                novaPrismStatement.close();
            }
            novaPrismConnection.close();
        }
    }
}
