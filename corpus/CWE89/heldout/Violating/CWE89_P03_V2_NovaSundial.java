import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P03_V2_NovaSundial {

    private void queryNovaSundial(String data) throws SQLException {
        Connection novaSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaSundial");
        Statement novaSundialStatement = null;
        ResultSet novaSundialRows = null;
        try {
            novaSundialStatement = novaSundialConnection.createStatement();
            novaSundialRows = novaSundialStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(novaSundialRows.getRow());
        } finally {
            if (novaSundialRows != null) {
                novaSundialRows.close();
            }
            if (novaSundialStatement != null) {
                novaSundialStatement.close();
            }
            novaSundialConnection.close();
        }
    }

    public void runNovaSundial() throws SQLException {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("NOVA_SUNDIAL_FILTER");
        }
        queryNovaSundial(data);
    }
}
