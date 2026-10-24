import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P05_V1_NovaCascadeSafe {

    private String novaCascadeData;

    private void queryNovaCascade() throws SQLException {
        String data = novaCascadeData;
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

    public void runNovaCascade() throws SQLException {
        String data;
        data = "foo";
        novaCascadeData = data;
        queryNovaCascade();
    }
}
