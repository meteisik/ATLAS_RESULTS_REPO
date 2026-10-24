import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V1_NovaCascade {

    public void runNovaCascade() throws SQLException {
        String data;
        data = (new CWE89_P07_V1_NovaCascadeSource()).loadNovaCascade();
        Connection novaCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaCascade");
        Statement novaCascadeStatement = null;
        ResultSet novaCascadeRows = null;
        try {
            novaCascadeStatement = novaCascadeConnection.createStatement();
            novaCascadeRows = novaCascadeStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(novaCascadeRows.getRow());
        } finally {
            if (novaCascadeRows != null) {
                novaCascadeRows.close();
            }
            if (novaCascadeStatement != null) {
                novaCascadeStatement.close();
            }
            novaCascadeConnection.close();
        }
    }
}

class CWE89_P07_V1_NovaCascadeSource {
    public String loadNovaCascade() {
        String data;
        data = System.getenv("NOVA_CASCADE_FILTER");
        return data;
    }
}
