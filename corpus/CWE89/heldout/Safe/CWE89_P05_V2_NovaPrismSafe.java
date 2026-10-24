import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P05_V2_NovaPrismSafe {

    private String novaPrismData;

    private void queryNovaPrism() throws SQLException {
        String data = novaPrismData;
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

    public void runNovaPrism() throws SQLException {
        String data;
        if (5 == 5) {
            data = "foo";
        } else {
            data = null;
        }
        novaPrismData = data;
        queryNovaPrism();
    }
}
